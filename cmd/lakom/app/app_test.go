// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

var _ = DescribeTable("Credential source flag defaults", func(args []string, useOnlyImagePullSecrets bool) {
	var options Options
	flags := pflag.NewFlagSet("lakom", pflag.ContinueOnError)
	options.AddFlags(flags)
	Expect(flags.Parse(args)).To(Succeed())
	Expect(options.UseOnlyImagePullSecrets).To(Equal(useOnlyImagePullSecrets))
},
	Entry("default", nil, true),
	Entry("explicit true", []string{"--use-only-image-pull-secrets=true"}, true),
	Entry("ambient credentials opt-in", []string{"--use-only-image-pull-secrets=false"}, false),
)
