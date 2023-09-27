/*
Copyright 2018 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
   http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This file was copied and modified from the kubernetes-sigs/controller-runtime project
https://github.com/kubernetes-sigs/controller-runtime/blob/4c9c9564e4652bbdec14a602d6196d8622500b51/pkg/webhook/admission/http_test.go
Modifications Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved.
*/

package admission_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gardener/gardener-extension-shoot-lakom-service/pkg/admission"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	admissionv1 "k8s.io/api/admission/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	cradmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var _ = Describe("Admission Webhooks", func() {

	const (
		gvkJSONv1      = `"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1"`
		gvkJSONv1beta1 = `"kind":"AdmissionReview","apiVersion":"admission.k8s.io/v1beta1"`
	)

	Describe("HTTP Handler", func() {
		var (
			logger       logr.Logger
			respRecorder *httptest.ResponseRecorder
			server       *admission.Server
		)

		BeforeEach(func() {
			logger = logf.Log
			respRecorder = &httptest.ResponseRecorder{
				Body: bytes.NewBuffer(nil),
			}

			server = &admission.Server{
				Log: logger,
			}
		})

		It("should return bad-request when given an empty body", func() {
			req := &http.Request{Body: nil}

			expected := `{"response":{"uid":"","allowed":false,"status":{"metadata":{},"message":"request body is empty","code":400}}}
`
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return bad-request when given the wrong content-type", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/foo"}},
				Body:   nopCloser{Reader: bytes.NewBuffer(nil)},
			}

			expected :=
				`{"response":{"uid":"","allowed":false,"status":{"metadata":{},"message":"contentType=application/foo, expected application/json","code":400}}}
`
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return bad-request when given an undecodable body", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString("{")},
			}

			expected :=
				`{"response":{"uid":"","allowed":false,"status":{"metadata":{},"message":"couldn't get version/kind; json parse error: unexpected end of JSON input","code":400}}}
`
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusBadRequest))
		})

		It("should return the response given by the handler with version defaulted to v1", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(`{"request":{}}`)},
			}
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{},
				},
				Log: logger.WithName("server"),
			}

			expected := fmt.Sprintf(`{%s,"response":{"uid":"","allowed":true,"status":{"metadata":{},"code":200}}}
`, gvkJSONv1)
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusOK))
		})

		It("should return the v1 response given by the handler", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(fmt.Sprintf(`{%s,"request":{}}`, gvkJSONv1))},
			}
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{},
				},
				Log: logger.WithName("server"),
			}

			expected := fmt.Sprintf(`{%s,"response":{"uid":"","allowed":true,"status":{"metadata":{},"code":200}}}
`, gvkJSONv1)
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusOK))
		})

		It("should return the v1beta1 response given by the handler", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(fmt.Sprintf(`{%s,"request":{}}`, gvkJSONv1beta1))},
			}
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{},
				},
				Log: logger.WithName("server"),
			}

			expected := fmt.Sprintf(`{%s,"response":{"uid":"","allowed":true,"status":{"metadata":{},"code":200}}}
`, gvkJSONv1beta1)
			server.ServeHTTP(respRecorder, req)
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusOK))
		})

		It("should present the Context from the HTTP request, if any", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(`{"request":{}}`)},
			}
			type ctxkey int
			const key ctxkey = 1
			const value = "from-ctx"
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{
						fn: func(ctx context.Context, req cradmission.Request) cradmission.Response {
							<-ctx.Done()
							return cradmission.Allowed(ctx.Value(key).(string))
						},
					},
				},
				Log: logger.WithName("server"),
			}

			expected := fmt.Sprintf(`{%s,"response":{"uid":"","allowed":true,"status":{"metadata":{},"message":%q,"code":200}}}
`, gvkJSONv1, value)

			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key, value))
			cancel()
			server.ServeHTTP(respRecorder, req.WithContext(ctx))
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusOK))
		})

		It("should mutate the Context from the HTTP request, if func supplied", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(`{"request":{}}`)},
			}
			type ctxkey int
			const key ctxkey = 1
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{
						fn: func(ctx context.Context, req cradmission.Request) cradmission.Response {
							return cradmission.Allowed(ctx.Value(key).(string))
						},
					},
					WithContextFunc: func(ctx context.Context, r *http.Request) context.Context {
						return context.WithValue(ctx, key, r.Header["Content-Type"][0])
					},
				},
				Log: logger.WithName("server"),
			}

			expected := fmt.Sprintf(`{%s,"response":{"uid":"","allowed":true,"status":{"metadata":{},"message":%q,"code":200}}}
`, gvkJSONv1, "application/json")

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			server.ServeHTTP(respRecorder, req.WithContext(ctx))
			Expect(respRecorder.Body.String()).To(Equal(expected))
			Expect(respRecorder.Code).To(Equal(http.StatusOK))
		})

		It("should never run into circular calling if the writer has broken", func() {
			req := &http.Request{
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   nopCloser{Reader: bytes.NewBufferString(fmt.Sprintf(`{%s,"request":{}}`, gvkJSONv1))},
			}
			server := admission.Server{
				Webhook: cradmission.Webhook{
					Handler: &fakeHandler{},
				},
				Log: logger.WithName("server"),
			}

			bw := &brokenWriter{ResponseWriter: respRecorder}
			Eventually(func() int {
				// This should not be blocked by the circular calling of writeResponse and writeAdmissionResponse
				server.ServeHTTP(bw, req)
				return respRecorder.Body.Len()
			}, time.Second*3).Should(Equal(0))
		})
	})
})

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error { return nil }

type fakeHandler struct {
	invoked        bool
	fn             func(context.Context, cradmission.Request) cradmission.Response
	decoder        *cradmission.Decoder
	injectedString string
}

func (h *fakeHandler) InjectDecoder(d *cradmission.Decoder) error {
	h.decoder = d
	return nil
}

func (h *fakeHandler) InjectString(s string) error {
	h.injectedString = s
	return nil
}

func (h *fakeHandler) Handle(ctx context.Context, req cradmission.Request) cradmission.Response {
	h.invoked = true
	if h.fn != nil {
		return h.fn(ctx, req)
	}
	return cradmission.Response{AdmissionResponse: admissionv1.AdmissionResponse{
		Allowed: true,
	}}
}

type brokenWriter struct {
	http.ResponseWriter
}

func (bw *brokenWriter) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("mock: write: broken pipe")
}
