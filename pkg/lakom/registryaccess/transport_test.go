// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package registryaccess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Destination rules", func() {
	for _, tc := range []struct {
		ip                           string
		defaultAllowed, optInAllowed bool
	}{
		{"8.8.8.8", true, true},
		{"2606:4700:4700::1111", true, true},
		{"10.20.30.40", false, true},
		{"10.20.30.41", false, false},
		{"172.16.0.1", false, false},
		{"192.168.1.1", false, false},
		{"100.64.1.1", false, true},
		{"100.100.100.200", false, false},
		{"fd12:3456::1", false, true},
		{"fd12:3456::2", false, false},
		{"127.0.0.1", false, false},
		{"169.254.169.254", false, false},
		{"0.0.0.0", false, false},
		{"0.1.2.3", false, false},
		{"224.0.0.1", false, false},
		{"255.255.255.255", false, false},
		{"::", false, false},
		{"::1", false, false},
		{"fe80::1", false, false},
		{"fec0::1", false, false},
		{"fe80::1%eth0", false, false},
		{"ff02::1", false, false},
		{"::ffff:127.0.0.1", false, false},
		{"::ffff:10.20.30.40", false, true},
		{"::ffff:169.254.169.254", false, false},
		{"64:ff9b::a9fe:a9fe", false, false},
		{"2002:a9fe:a9fe::1", false, false},
	} {
		It(tc.ip, func() {
			t := GinkgoT()
			allowed, err := ParseAllowedPrivateRegistryCIDRs([]string{"10.20.30.40/32", "fd12:3456::1/128", "100.64.0.0/10"})
			Expect(err).NotTo(HaveOccurred())
			ip := netip.MustParseAddr(tc.ip)
			if got := destinationAllowed(ip, nil); got != tc.defaultAllowed {
				t.Errorf("default: got %v, want %v", got, tc.defaultAllowed)
			}
			if got := destinationAllowed(ip, allowed); got != tc.optInAllowed {
				t.Errorf("opt-in: got %v, want %v", got, tc.optInAllowed)
			}
		})
	}
})

var _ = Describe("Invalid private registry CIDRs", func() {
	for _, cidr := range []string{"invalid", "10.1.2.3", "10.1.2.3/24", "0.0.0.0/0", "::/0", "127.0.0.1/32", "169.254.169.254/32", "100.100.100.200/32", "8.8.8.8/32", "::ffff:10.0.0.0/104"} {
		It(cidr, func() {
			t := GinkgoT()
			if _, err := NewTransport([]string{cidr}); err == nil {
				t.Fatal("invalid CIDR accepted")
			}
		})
	}
})

var _ = Describe("Resolved addresses", func() {
	for _, tc := range []struct {
		name, host string
		answers    []netip.Addr
		allowed    bool
	}{
		{"public DNS", "registry.example", []netip.Addr{netip.MustParseAddr("8.8.8.8")}, true},
		{"private DNS", "registry.example", []netip.Addr{netip.MustParseAddr("10.0.0.1")}, false},
		{"mixed DNS", "registry.example", []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, false},
		{"empty DNS", "registry.example", nil, false},
		{"literal public", "8.8.8.8", nil, true},
		{"literal loopback", "127.0.0.1", nil, false},
	} {
		It(tc.name, func() {
			t := GinkgoT()
			lookups, dials := 0, 0
			dialer := restrictedDialer{
				lookup: func(context.Context, string, string) ([]netip.Addr, error) {
					lookups++
					if lookups > 1 {
						t.Fatal("hostname was resolved again")
					}
					return tc.answers, nil
				},
				dial: func(_ context.Context, _, address string) (net.Conn, error) {
					dials++
					if address != "8.8.8.8:443" {
						t.Fatalf("dialed unchecked address %q", address)
					}
					return nil, errors.New("test dial")
				},
			}
			_, err := dialer.DialContext(context.Background(), "tcp", net.JoinHostPort(tc.host, "443"))
			if err == nil {
				t.Fatal("expected test dial failure or policy rejection")
			}
			if (dials > 0) != tc.allowed {
				t.Fatalf("dials = %d, allowed = %v", dials, tc.allowed)
			}
			if _, err := netip.ParseAddr(tc.host); err == nil && lookups != 0 {
				t.Fatal("literal IP triggered DNS lookup")
			}
		})
	}
})

var _ = Describe("Registry requests", func() {
	for _, scenario := range []string{"public registry", "private registry opt-in", "redirect", "authentication realm"} {
		It(scenario, func() {
			t := GinkgoT()
			var requests, blockedLookups atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				switch {
				case scenario == "redirect":
					http.Redirect(w, r, "http://metadata.example/token", http.StatusTemporaryRedirect)
				case scenario == "authentication realm":
					w.Header().Set("WWW-Authenticate", "Bearer realm=\"http://metadata.example/token\",service=\"registry.example\"")
					w.WriteHeader(http.StatusUnauthorized)
				case r.URL.Path == "/v2/":
					w.WriteHeader(http.StatusOK)
				default:
					w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
					w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
					w.Header().Set("Content-Length", "0")
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			cidrs := []string(nil)
			ip := netip.MustParseAddr("8.8.8.8")
			if scenario == "private registry opt-in" {
				cidrs = []string{"10.20.30.40/32"}
				ip = netip.MustParseAddr("10.20.30.40")
			}
			transport, err := NewTransport(cidrs)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			if transport.Proxy != nil {
				t.Fatal("proxy could bypass destination checks")
			}
			prefixes, err := ParseAllowedPrivateRegistryCIDRs(cidrs)
			if err != nil {
				t.Fatal(err)
			}
			transport.DialContext = restrictedDialer{
				allowed: prefixes,
				lookup: func(_ context.Context, _, host string) ([]netip.Addr, error) {
					if host == "registry.example" {
						return []netip.Addr{ip}, nil
					}
					blockedLookups.Add(1)
					return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
				},
				dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != net.JoinHostPort(ip.String(), "80") && address != net.JoinHostPort(ip.String(), "443") {
						return nil, fmt.Errorf("unchecked target dialed: %s", address)
					}
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				},
			}.DialContext
			ref, err := name.NewTag("registry.example/image:tag", name.Insecure)
			if err != nil {
				t.Fatal(err)
			}
			_, err = remote.Head(ref, remote.WithTransport(transport), remote.WithAuth(authn.Anonymous))
			if requests.Load() == 0 {
				t.Fatal("registry was not contacted")
			}
			if scenario == "redirect" || scenario == "authentication realm" {
				if err == nil || !strings.Contains(err.Error(), "registry destination is not allowed") {
					t.Fatalf("expected destination rejection, got %v", err)
				}
				if blockedLookups.Load() == 0 {
					t.Fatal("secondary target was not checked")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
})

var _ = It("preserves HTTP and TLS hostnames", func() {
	t := GinkgoT()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer GinkgoRecover()
		if r.Host != "example.com" {
			t.Errorf("HTTP host was changed to %q", r.Host)
		}
		if r.TLS.ServerName != "example.com" {
			t.Errorf("TLS server name was changed to %q", r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	transport, err := NewTransport(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.DialContext = restrictedDialer{
		lookup: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "8.8.8.8:443" {
				return nil, fmt.Errorf("unexpected dial target %q", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}.DialContext
	client := &http.Client{Transport: transport}
	response, err := client.Get("https://example.com/v2/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", response.StatusCode)
	}
})
