// Copyright (c) 2023-2026, R.I. Pienaar and the Choria Project contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strings"

	"github.com/choria-io/fisk"
	"github.com/expr-lang/expr"
)

// FiskValidator is a fisk.OptionValidator that compatible with Validator() on arguments and flags
func FiskValidator(validation string) fisk.OptionValidator {
	return func(value string) error {
		ok, err := Validate(value, validation)
		if err != nil {
			return fmt.Errorf("validation using %q failed: %w", validation, err)
		}

		if !ok {
			return fmt.Errorf("validation using %q did not pass", validation)
		}

		return nil
	}
}

// SurveyValidator is a validator for github.com/AlecAivazis/survey
func SurveyValidator(validation string, required bool) func(any) error {
	return func(v any) error {
		val, ok := v.(string)
		if !ok {
			return fmt.Errorf("unsupported validation type")
		}

		if !required && len(val) == 0 {
			return nil
		}

		ok, err := Validate(v, validation)
		if err != nil {
			return fmt.Errorf("validation using %q failed: %w", validation, err)
		}

		if !ok {
			return fmt.Errorf("validation using %q did not pass", validation)
		}

		return nil
	}
}

// Validate validates value using the expr expression validation
func Validate(value any, validation string) (bool, error) {
	var env any

	vs, ok := value.(string)
	if ok {
		env = map[string]any{
			"value": vs,
			"Value": vs,
		}
	} else {
		env = value
	}

	opts := []expr.Option{
		expr.Env(env), expr.AsBool(),
	}
	opts = append(opts, ShellSafeValidator()...)
	opts = append(opts, IPv4Validator()...)
	opts = append(opts, IPv6Validator()...)
	opts = append(opts, IPvValidator()...)
	opts = append(opts, IntValidator()...)
	opts = append(opts, FloatValidator()...)
	opts = append(opts, RegexValidator()...)
	opts = append(opts, DurationValidator()...)
	opts = append(opts, HostnameValidator()...)
	opts = append(opts, FQDNValidator()...)

	program, err := expr.Compile(validation, opts...)
	if err != nil {
		return false, err
	}

	output, err := expr.Run(program, env)
	if err != nil {
		return false, err
	}

	return output.(bool), nil
}

func FloatValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		_, _, err := big.ParseFloat(params[0].(string), 10, 256, big.ToNearestEven)
		return err == nil, nil
	}

	return []expr.Option{
		expr.Function("isFloat", f, new(func(string) (bool, error))),
		expr.Function("is_float", f, new(func(string) (bool, error))),
	}
}

func IntValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		_, ok := new(big.Int).SetString(params[0].(string), 10)
		return ok, nil
	}

	return []expr.Option{
		expr.Function("isInt", f, new(func(string) (bool, error))),
		expr.Function("is_int", f, new(func(string) (bool, error))),
	}
}

func IPvValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)
		ip := net.ParseIP(val)

		if ip == nil {
			return false, fmt.Errorf("%s is not an IP address", val)
		}

		return true, nil
	}

	return []expr.Option{
		expr.Function("isIP", f, new(func(string) (bool, error))),
		expr.Function("is_ip", f, new(func(string) (bool, error))),
	}
}

func IPv4Validator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)
		ip := net.ParseIP(val).To4()

		if ip == nil {
			return false, fmt.Errorf("%s is not an IPv4 address", val)
		}

		return true, nil
	}

	return []expr.Option{
		expr.Function("isIPv4", f, new(func(string) (bool, error))),
		expr.Function("is_ipv4", f, new(func(string) (bool, error))),
	}
}

func IPv6Validator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)
		ip := net.ParseIP(val)

		if ip == nil {
			return false, fmt.Errorf("%s is not an IPv6 address", val)
		}

		if ip.To4() != nil {
			return false, fmt.Errorf("%s is not an IPv6 address", val)
		}

		return true, nil
	}
	return []expr.Option{
		expr.Function("isIPv6", f, new(func(string) (bool, error))),
		expr.Function("is_ipv6", f, new(func(string) (bool, error))),
	}
}

func DurationValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		_, err := fisk.ParseDuration(params[0].(string))
		return err == nil, nil
	}

	return []expr.Option{
		expr.Function("isDuration", f, new(func(string) (bool, error))),
		expr.Function("is_duration", f, new(func(string) (bool, error))),
	}
}

func RegexValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)
		pattern := params[1].(string)

		matched, err := regexp.MatchString(pattern, val)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", pattern, err)
		}

		return matched, nil
	}

	return []expr.Option{
		expr.Function("isRegex", f, new(func(string, string) (bool, error))),
		expr.Function("is_regex", f, new(func(string, string) (bool, error))),
	}
}

func ShellSafeValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := strings.TrimSpace(params[0].(string))
		badChars := []string{"`", "$", ";", "|", "&", ">", "<", "(", ")", "\n"}

		for _, c := range badChars {
			if strings.Contains(val, c) {
				return false, fmt.Errorf("may not contain '%s'", c)
			}
		}

		return true, nil
	}

	return []expr.Option{
		expr.Function("isShellSafe", f, new(func(string) (bool, error))),
		expr.Function("is_shellsafe", f, new(func(string) (bool, error))),
	}
}

var (
	hostnameRegexRFC1123 = regexp.MustCompile(`^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62}){1}(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?$`)
	fqdnRegexRFC1123     = regexp.MustCompile(`^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?(\.[a-zA-Z]{1}[a-zA-Z0-9-]{0,62})\.?$`)
)

func HostnameValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)

		if !hostnameRegexRFC1123.MatchString(val) {
			return false, fmt.Errorf("%q is not a valid hostname", val)
		}

		return true, nil
	}

	return []expr.Option{
		expr.Function("isHostname", f, new(func(string) (bool, error))),
		expr.Function("is_hostname", f, new(func(string) (bool, error))),
	}
}

func FQDNValidator() []expr.Option {
	f := func(params ...any) (any, error) {
		val := params[0].(string)

		if !fqdnRegexRFC1123.MatchString(val) {
			return false, fmt.Errorf("%q is not a valid FQDN", val)
		}

		return true, nil
	}

	return []expr.Option{
		expr.Function("isFQDN", f, new(func(string) (bool, error))),
		expr.Function("is_fqdn", f, new(func(string) (bool, error))),
	}
}
