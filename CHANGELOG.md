# Changelog

## [Unreleased]
## Added
 * This CHANGELOG.md file

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