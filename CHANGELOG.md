# Changelog

## [1.3.2](https://github.com/Password4j/password4j/releases/tag/1.3.2) - (2020-09-09)
### Fixed
 *  The location of the configuration file is now customizable ([#5](../../issues/5))
### Security
 *  `SecureString.toString()` now hides the length of the string ([#6](../../issues/6))

## [1.3.1](https://github.com/Password4j/password4j/releases/tag/1.3.1) - (2020-03-25)
### Fixed
 *  `toString()` of some `HashingFunction` produced non-unique output ([#3](../../issues/3))
 *  added missing getters for some `HashingFunction`s ([#4](../../issues/4))

## [1.3.0](https://github.com/Password4j/password4j/releases/tag/1.3.0) - (2020-03-19)
### Added
 * Capability of updating the hash (re-hash) with a new configuration just after the verification process
### Changed
 * `HashBuilder` and `HashChecker` are less extendable because there are more maintainability issues than effective advantages
 * Pepper can be provided either with `SecureString` or `String`.
### Removed
 * `Password.hash()` and `Password.check()` methods that accepts a custom `HashBuilder` or a custom `HashChecker`

## [1.2.1](https://github.com/Password4j/password4j/releases/tag/1.2.1) - (2020-03-17)
### Added
 * Constant time equality in `SecureString`
### Changed
 * Enum `WithHmac` renamed to `Hmac`

## [1.2.0](https://github.com/Password4j/password4j/releases/tag/1.2.0) - (2020-03-15)
### Added
 * This CHANGELOG.md file
### Security
 * Plain text passwords can be provided either with `SecureString` or `String`.

## [1.1.0](https://github.com/Password4j/password4j/releases/tag/1.1.0) - (2020-03-14)
### Added
 * Configurable delimiter for `CompressedPBKDF2Function` (before was `$`)
### Removed
 * `Hash.check()` method because `Password.check()` should be the only way to verify passwords.
### Fixed
 * Values from `psw4j.properties` are not properly cached.
 * Typos in README.md
 * Typos in `SystemChecker`'s methods' signature. 

## [1.0.2](https://github.com/Password4j/password4j/releases/tag/1.0.2) - (2020-03-12)
### Change
 * `SystemChecker.java` has no more a `main` method but must be called from end user's code.
 Removed UI and execution from Maven profile.

## [1.0.1](https://github.com/Password4j/password4j/releases/tag/password4j-1.0.1)  - (2020-03-11)
### Change
 * POM structure and dependencies

## [1.0.0](https://github.com/Password4j/password4j/releases/tag/1.0.0) - (2020-03-11)
### Change
 * API are more readable for end users
