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
https://github.com/kubernetes-sigs/controller-runtime/blob/4c9c9564e4652bbdec14a602d6196d8622500b51/pkg/webhook/admission/admission_suite_test.go

Modifications Copyright 2022 SAP SE or an SAP affiliate company and Gardener contributors
*/

package admission

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestAdmissionWebhook(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Admission Webhook Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
})
