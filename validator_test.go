// Copyright (c) 2023-2026, R.I. Pienaar and the Choria Project contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestBuilder(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Validator")
}

var _ = Describe("Validator", func() {
	Describe("is_ip", func() {
		It("Should validate correctly", func() {
			ok, err := Validate("1.1.1.1", "is_ip(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("2a00:1450:4002:405::20", "is_ip(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("bob", "is_ip(value)")
			Expect(err.Error()).To(ContainSubstring("bob is not an IP address"))
			Expect(ok).To(BeFalse())
		})
	})

	Describe("is_ipv4", func() {
		It("Should validate correctly", func() {
			ok, err := Validate("1.1.1.1", "is_ipv4(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("2a00:1450:4002:405::20", "is_ipv4(value)")
			Expect(err.Error()).To(ContainSubstring("2a00:1450:4002:405::20 is not an IPv4 address"))
			Expect(ok).To(BeFalse())
		})
	})

	Describe("is_ipv6", func() {
		It("Should validate correctly", func() {
			ok, err := Validate("2a00:1450:4002:405::20", "is_ipv6(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("1.1.1.1", "is_ipv6(value)")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("1.1.1.1 is not an IPv6 address"))
			Expect(ok).To(BeFalse())
		})
	})

	Describe("is_int", func() {
		It("Should validate integers", func() {
			ok, err := Validate("1", "is_int(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("-42", "is_int(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("0", "is_int(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("Should reject non-integers", func() {
			ok, err := Validate("bob", "is_int(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())

			ok, err = Validate("1.5", "is_int(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should work with isInt alias", func() {
			ok, err := Validate("1", "isInt(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("is_float", func() {
		It("Should validate floats", func() {
			ok, err := Validate("1.5", "is_float(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("-3.14", "is_float(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("42", "is_float(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("Should reject non-floats", func() {
			ok, err := Validate("bob", "is_float(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should work with isFloat alias", func() {
			ok, err := Validate("1.5", "isFloat(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("is_duration", func() {
		It("Should validate durations", func() {
			ok, err := Validate("1h", "is_duration(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("5m", "is_duration(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("1d", "is_duration(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("Should reject non-durations", func() {
			ok, err := Validate("bob", "is_duration(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should work with isDuration alias", func() {
			ok, err := Validate("30s", "isDuration(value)")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("is_regex", func() {
		It("Should match valid patterns", func() {
			ok, err := Validate("hello123", `is_regex(value, "^[a-z]+[0-9]+$")`)
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("Should reject non-matching values", func() {
			ok, err := Validate("hello", `is_regex(value, "^[0-9]+$")`)
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should return error for invalid regex", func() {
			ok, err := Validate("hello", `is_regex(value, "[invalid")`)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid regex"))
			Expect(ok).To(BeFalse())
		})

		It("Should work with isRegex alias", func() {
			ok, err := Validate("test", `isRegex(value, "^test$")`)
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("shellsafe", func() {
		It("Should match bad strings", func() {
			badchars := []string{"`", "$", ";", "|", "&", ">", "<", "(", ")"}

			for _, c := range badchars {
				ok, err := Validate(fmt.Sprintf("thing%sthing", c), "is_shellsafe(value)")
				Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("may not contain '%s'", c)))
				Expect(ok).To(BeFalse())
			}
		})

		It("Should reject newlines", func() {
			ok, err := Validate("thing\nthing", "is_shellsafe(value)")
			Expect(err).To(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should allow good things", func() {
			Expect(Validate("ok", "is_shellsafe(value)")).To(BeTrue())
			Expect(Validate("", "is_shellsafe(value)")).To(BeTrue())
			Expect(Validate("ok ok ok", "is_shellsafe(value)")).To(BeTrue())
		})

		It("Should work with isShellSafe alias", func() {
			Expect(Validate("ok", "isShellSafe(value)")).To(BeTrue())
		})
	})

	Describe("Validate", func() {
		It("Should support compound expressions", func() {
			ok, err := Validate("hello", "value == 'hello'")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())

			ok, err = Validate("hello", "value == 'world'")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeFalse())
		})

		It("Should support the Value alias", func() {
			ok, err := Validate("hello", "Value == 'hello'")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})

		It("Should return error for invalid expressions", func() {
			_, err := Validate("hello", "not_a_function(value)")
			Expect(err).To(HaveOccurred())
		})

		It("Should handle non-string values", func() {
			env := map[string]any{"value": 42}
			ok, err := Validate(env, "value == 42")
			Expect(err).ToNot(HaveOccurred())
			Expect(ok).To(BeTrue())
		})
	})

	Describe("FiskValidator", func() {
		It("Should return nil for valid input", func() {
			v := FiskValidator("is_ip(value)")
			Expect(v("1.1.1.1")).To(Succeed())
		})

		It("Should return error for invalid input", func() {
			v := FiskValidator("is_ip(value)")
			err := v("bob")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("validation using"))
		})

		It("Should return error when validation returns false without error", func() {
			v := FiskValidator("is_int(value)")
			err := v("bob")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("did not pass"))
		})

		It("Should return error for invalid expressions", func() {
			v := FiskValidator("broken(")
			err := v("anything")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed"))
		})
	})

	Describe("SurveyValidator", func() {
		It("Should return nil for valid input", func() {
			v := SurveyValidator("is_ip(value)", true)
			Expect(v("1.1.1.1")).To(Succeed())
		})

		It("Should return error for invalid input", func() {
			v := SurveyValidator("is_ip(value)", true)
			err := v("bob")
			Expect(err).To(HaveOccurred())
		})

		It("Should return error when validation returns false without error", func() {
			v := SurveyValidator("is_int(value)", true)
			err := v("bob")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("did not pass"))
		})

		It("Should allow empty values when not required", func() {
			v := SurveyValidator("is_ip(value)", false)
			Expect(v("")).To(Succeed())
		})

		It("Should reject empty values when required", func() {
			v := SurveyValidator("is_ip(value)", true)
			err := v("")
			Expect(err).To(HaveOccurred())
		})

		It("Should return error for non-string input", func() {
			v := SurveyValidator("is_ip(value)", true)
			err := v(42)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported validation type"))
		})

		It("Should return error for invalid expressions", func() {
			v := SurveyValidator("broken(", true)
			err := v("anything")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed"))
		})
	})

	Describe("is_ipv6", func() {
		It("Should reject non-IP values", func() {
			ok, err := Validate("bob", "is_ipv6(value)")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("bob is not an IPv6 address"))
			Expect(ok).To(BeFalse())
		})
	})
})
