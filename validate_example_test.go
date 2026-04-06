// Copyright (c) 2023-2026, R.I. Pienaar and the Choria Project contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import "fmt"

func ExampleValidate_ipAddress() {
	ok, err := Validate("1.1.1.1", "is_ipv4(value)")
	fmt.Printf("valid: %v, err: %v\n", ok, err)

	ok, _ = Validate("bob", "is_ipv4(value)")
	fmt.Printf("valid: %v\n", ok)

	// Output:
	// valid: true, err: <nil>
	// valid: false
}

func ExampleValidate_shellSafe() {
	ok, err := Validate("safe-input", "is_shellsafe(value)")
	fmt.Printf("valid: %v, err: %v\n", ok, err)

	ok, _ = Validate("bad;input", "is_shellsafe(value)")
	fmt.Printf("valid: %v\n", ok)

	// Output:
	// valid: true, err: <nil>
	// valid: false
}

func ExampleValidate_regex() {
	ok, err := Validate("hello123", `is_regex(value, "^[a-z]+[0-9]+$")`)
	fmt.Printf("valid: %v, err: %v\n", ok, err)

	ok, err = Validate("HELLO", `is_regex(value, "^[a-z]+$")`)
	fmt.Printf("valid: %v, err: %v\n", ok, err)

	// Output:
	// valid: true, err: <nil>
	// valid: false, err: <nil>
}

func ExampleValidate_compound() {
	ok, err := Validate("hello", "is_shellsafe(value) && value == 'hello'")
	fmt.Printf("valid: %v, err: %v\n", ok, err)

	// Output:
	// valid: true, err: <nil>
}

func ExampleValidate_numeric() {
	ok, _ := Validate("42", "is_int(value)")
	fmt.Printf("is_int: %v\n", ok)

	ok, _ = Validate("3.14", "is_float(value)")
	fmt.Printf("is_float: %v\n", ok)

	// Output:
	// is_int: true
	// is_float: true
}

func ExampleValidate_duration() {
	ok, _ := Validate("1h30m", "is_duration(value)")
	fmt.Printf("valid: %v\n", ok)

	ok, _ = Validate("bob", "is_duration(value)")
	fmt.Printf("valid: %v\n", ok)

	// Output:
	// valid: true
	// valid: false
}

func ExampleFiskValidator() {
	v := FiskValidator("is_int(value)")

	err := v("42")
	fmt.Printf("err: %v\n", err)

	err = v("bob")
	fmt.Printf("err: %v\n", err)

	// Output:
	// err: <nil>
	// err: validation using "is_int(value)" did not pass
}

func ExampleSurveyValidator() {
	v := SurveyValidator("is_int(value)", true)

	err := v("42")
	fmt.Printf("err: %v\n", err)

	err = v("bob")
	fmt.Printf("err: %v\n", err)

	// Output:
	// err: <nil>
	// err: validation using "is_int(value)" did not pass
}
