# Changelog

# [1.8.2](https://github.com/Password4j/password4j/releases/tag/1.8.2) - (2024-05-01)
### Fixed
*  Multi thread algorithms use daemon threads in order to not block the application shutdown if there is no explicit `System.exit()` ([#151](../../issues/151))
*  Password4j works even when there is no access to `psw4j.properties` file due to restrictive security policies ([#153](../../issues/153))


## [1.8.1](https://github.com/Password4j/password4j/releases/tag/1.8.1) - (2024-03-08)
### Fixed
* `Argon2Function#internalHash(...)` used a double conversion from `byte[]` to `String` and back to `byte[]` that created inconsistencies in `Hash#salt  ([#143](../../issues/143))

### Changed
* `Hash#Hash(HashingFunction, String, byte[], String)` marked deprecated

## [1.8.0](https://github.com/Password4j/password4j/releases/tag/1.8.0) - (2024-03-03)
### Added
* Balloon Hashing implementation ([#131](../../issues/131))

### Fixed
* Parallelism is achieved by an `ExecutorService` instantiated during object creation instead of during the hashing process

### Changed
* Banner is disabled by default

## [1.7.3](https://github.com/Password4j/password4j/releases/tag/1.7.3) - (2023-09-14)
### Fixed
* Wrong hashes when the password contains non ISO 8859-1 characters ([#126](../../issues/126))


## [1.7.2](https://github.com/Password4j/password4j/releases/tag/1.7.2) - (2023-08-20)
### Fixed
* Suppressed warning for usage of `java.security.AccessController`. This is how the java development team fixed the problem for the moment ([#119](../../issues/119))
* In some custom JDK implementations `java.security.Provider#getServices()` can return `null` instead of empty `java.security.Provider.Service[]` ([#120](../../issues/120))


## [1.7.1](https://github.com/Password4j/password4j/releases/tag/1.7.1) - (2023-06-02)
### Fixed
* Bcrypt used negative rounds when cost factor = 31 ([#114](../../issues/114))

## [1.7.0](https://github.com/Password4j/password4j/releases/tag/1.7.0) - (2023-02-18)
### Added
* APIs now accepts `byte[]` arguments ([#99](../../issues/99))
* `.forceUpdate()` forces Password4j to recalculate a new hash even if the parameters didn't change ([#102](../../issues/102))
* configurable salt length with property `global.salt.length` when using `#addRandomSalt()` ([#97](../../issues/97))
### Changed
* `.andUpdate()` no more recalculations of the hash if the algorithm, salt or pepper changed from the hash found in `Password.check()` ([#102](../../issues/102))
### Fixed
* Inconsistency between public and internal APIs for Argon2 ([#93](../../issues/93))

## [1.6.3](https://github.com/Password4j/password4j/releases/tag/1.6.3) - (2022-12-08)
### Fixed
* Inconsistency of Argon2 with some kind of salts generated from external libraries [#92](../../issues/92)

## [1.6.2](https://github.com/Password4j/password4j/releases/tag/1.6.2) - (2022-10-20)
### Added
* Application banner ([#83](../../issues/83)).
### Fixed
* Typo for issue [#80](../../issues/80)
### Removed
* Dependencies to Apache Commons Text, which had been vulnerable to arbitrary code execution in the past ([#84](../../issues/84)).

## [1.6.1](https://github.com/Password4j/password4j/releases/tag/1.6.1) - (2022-10-07)
### Changed
* Algorithms' default values are aligned to [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) ([#80](../../issues/80))

## [1.6.0](https://github.com/Password4j/password4j/releases/tag/1.6.0) - (2022-06-17)
### Changed
* `BCryptFunction`, `SCryptFunction`, `#withBCrypt()`, `#withSCrypt()`, `getBCryptInstance()`, `getSCryptInstance()` to `BcryptFunction`, `ScryptFunction`, `#withBcrypt()`, `#withScrypt()`, `getBcryptInstance()`, `getScryptInstance()` ([#36](../../issues/36)).
### Fixed
* Scrypt never prepends `$s0` to the result ([#64](../../issues/64)).

## [1.5.4](https://github.com/Password4j/password4j/releases/tag/1.5.4) - (2021-11-19)
### Fixed
* Removed `slf4j-nop` which can cause issues if not excluded from the dependency tree ([#46](../../issues/46)) 

## [1.5.3](https://github.com/Password4j/password4j/releases/tag/1.5.3) - (2021-04-14)
### Fixed
* `byte[]` are converted to `String` with environment-based encoding instead of UTF-8 ([#35](../../issues/35) and [#16](../../issues/16)).

## [1.5.2](https://github.com/Password4j/password4j/releases/tag/1.5.2) - (2021-02-21)
### Changed
* Raised the compatibility with Android API level from 26+ (Android 8.0) to 21+ (Android 5.0).
* `SystemChecker`'s benchmark tools returns a prototype of the function and the real elapsed time ([#23](../../issues/23)).
### Fixed
* Argon2 was not using the given pepper with `Password.check(String, Hash)`.
* Salt was converted from `String` to `byte[]` too many times. ([#31](../../issues/31)).
### Removed
* Dependency with Apache Commons Text.

## [1.5.1](https://github.com/Password4j/password4j/releases/tag/1.5.1) - (2021-02-05)
### Added
* `Hash` stores the byte array containing the calculated hash without algorithm's parameters and salt ([#26](../../issues/26)).
### Changed
* Scrypt accepts dynamic key length ([#24](../../issues/24)).
### Fixed
* Improved `toString()` methods' readability.

## [1.5.0](https://github.com/Password4j/password4j/releases/tag/1.5.0) - (2021-02-02)
### Added
* Argon2 support.
### Changed
* Enums `BCrypt` and `Hmac` are moved from `com.password4j` to `com.password4j.types`.
### Fixed
* Some typos along the code.

## [1.4.0](https://github.com/Password4j/password4j/releases/tag/1.4.0) - (2020-11-15)
### Added
 * CHFs like MD5, SHA-1, SHA-2 and SHA-3 in order to increase compatibility with legacy systems.
### Changed
 * `PBKDF2Function.getAlgorithm()` returns a `String` instead of an `Hmac` enum. This make `PBKDF2Function.toString()` and `CompressedPBKDF2Function.toString()` more readable. 
 * `SystemChecker.isPBKDF2Supported()` accepts a `String` instead of an `Hmac` enum.
### Fixed
 * Some typos along the code.

## [1.3.2](https://github.com/Password4j/password4j/releases/tag/1.3.2) - (2020-09-09)
### Fixed
 *  The location of the configuration file is now customizable ([#5](../../issues/5)).
### Security
 *  `SecureString.toString()` now hides the length of the string ([#6](../../issues/6)).

## [1.3.1](https://github.com/Password4j/password4j/releases/tag/1.3.1) - (2020-03-25)
### Fixed
 *  `toString()` of some `HashingFunction` produced non-unique output ([#3](../../issues/3)).
 *  added missing getters for some `HashingFunction`s ([#4](../../issues/4)).

## [1.3.0](https://github.com/Password4j/password4j/releases/tag/1.3.0) - (2020-03-19)
### Added
 * Capability of updating the hash (re-hash) with a new configuration just after the verification process.
### Changed
 * `HashBuilder` and `HashChecker` are less extendable because there are more maintainability issues than effective advantages
 * Pepper can be provided either with `SecureString` or `String`.
### Removed
 * `Password.hash()` and `Password.check()` methods that accepts a custom `HashBuilder` or a custom `HashChecker`.

## [1.2.1](https://github.com/Password4j/password4j/releases/tag/1.2.1) - (2020-03-17)
### Added
 * Constant time equality in `SecureString`.
### Changed
 * Enum `WithHmac` renamed to `Hmac`.

## [1.2.0](https://github.com/Password4j/password4j/releases/tag/1.2.0) - (2020-03-15)
### Added
 * This CHANGELOG.md file.
### Security
 * Plain text passwords can be provided either with `SecureString` or `String`.

## [1.1.0](https://github.com/Password4j/password4j/releases/tag/1.1.0) - (2020-03-14)
### Added
 * Configurable delimiter for `CompressedPBKDF2Function` (before was `$`).
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
 * POM structure and dependencies.

## [1.0.0](https://github.com/Password4j/password4j/releases/tag/1.0.0) - (2020-03-11)
### Change
 * API are more readable for end users.
