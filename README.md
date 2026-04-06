# Validator Library

This is a shared package in use by various Choria projects that provide input validation:

Validation is done using an expression language called [Expr](https://expr-lang.org) meaning multiple expressions can be combined.

It provides:

 - A generic Go validator library
 - A Validator compatible with [Fisk](https://github.com/choria-io/fisk)
 - A Validator compatible with [Survey](https://github.com/AlecAivazis/survey)

It provides the following validators:

| Validator                      | Description                                                                          |
|--------------------------------|--------------------------------------------------------------------------------------|
| `is_ip` / `isIP`               | Validates the value is a valid IP address (IPv4 or IPv6)                             |
| `is_ipv4` / `isIPv4`           | Validates the value is a valid IPv4 address                                          |
| `is_ipv6` / `isIPv6`           | Validates the value is a valid IPv6 address                                          |
| `is_int` / `isInt`             | Validates the value is an integer                                                    |
| `is_float` / `isFloat`         | Validates the value is a floating point number                                       |
| `is_duration` / `isDuration`   | Validates the value is a valid duration using `fisk.ParseDuration`                   |
| `is_regex` / `isRegex`         | Validates the value matches a regular expression, e.g. `is_regex(value, "^[a-z]+$")` |
| `is_shellsafe` / `isShellSafe` | Validates the value does not contain shell-unsafe characters                         |
