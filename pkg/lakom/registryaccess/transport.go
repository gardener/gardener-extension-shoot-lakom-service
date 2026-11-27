// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

// Package registryaccess restricts the destinations of registry HTTP requests.
package registryaccess

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var privateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// These destinations must not be used as registry, token-service, or redirect targets,
// even when an operator allows a private network containing them.
var excludedNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.100.100.200/32"), // Cloud metadata service in shared address space.
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"), // Well-known IPv4 translation prefix.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"), // Teredo.
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4.
	netip.MustParsePrefix("fec0::/10"), // Deprecated site-local addresses.
}

// ParseAllowedPrivateRegistryCIDRs validates operator-configured exceptions. Each
// prefix must be contained in an RFC1918, shared-address, or IPv6 unique-local network.
func ParseAllowedPrivateRegistryCIDRs(cidrs []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowedPrivateRegistryCIDRs entry %q: %w", cidr, err)
		}
		contained := false
		for _, network := range privateNetworks {
			if prefix.Bits() >= network.Bits() && network.Contains(prefix.Addr()) {
				contained = true
				break
			}
		}
		if !contained || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("allowedPrivateRegistryCIDRs entry %q must be within a private network", cidr)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("allowedPrivateRegistryCIDRs entry %q must be a network prefix without host bits", cidr)
		}
		if prefix.Bits() == prefix.Addr().BitLen() && !destinationAllowed(prefix.Addr(), []netip.Prefix{prefix}) {
			return nil, fmt.Errorf("allowedPrivateRegistryCIDRs entry %q is a reserved destination", cidr)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// NewTransport creates a registry-only transport. Every new connection is checked
// after DNS resolution and dials the checked IP, preventing a second DNS lookup.
// Redirects and registry authentication requests use this same transport. Proxies
// are disabled because proxy-side DNS resolution would bypass these checks.
func NewTransport(cidrs []string) (*http.Transport, error) {
	prefixes, err := ParseAllowedPrivateRegistryCIDRs(cidrs)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := remote.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = restrictedDialer{
		allowed: prefixes,
		lookup:  net.DefaultResolver.LookupNetIP,
		dial:    dialer.DialContext,
	}.DialContext
	return transport, nil
}

type restrictedDialer struct {
	allowed []netip.Prefix
	lookup  func(context.Context, string, string) ([]netip.Addr, error)
	dial    func(context.Context, string, string) (net.Conn, error)
}

func (d restrictedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = d.lookup(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("registry hostname resolved to no addresses")
	}
	// Reject mixed answers as well, before opening any connection.
	for _, ip := range addresses {
		if !destinationAllowed(ip, d.allowed) {
			return nil, errors.New("registry destination is not allowed")
		}
	}
	var dialErrors []error
	for _, ip := range addresses {
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(dialErrors...)
}

func destinationAllowed(ip netip.Addr, allowed []netip.Prefix) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range excludedNetworks {
		if prefix.Contains(ip) {
			return false
		}
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			for _, prefix := range allowed {
				if prefix.Contains(ip) {
					return true
				}
			}
			return false
		}
	}
	return true
}
