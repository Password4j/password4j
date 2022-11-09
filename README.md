# ![Build Status](https://i.imgur.com/eiL5IJp.png)

[![Build Status](https://github.com/Password4j/password4j/actions/workflows/build.yml/badge.svg)](https://github.com/Password4j/password4j/actions/workflows/build.yml)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.password4j/password4j/badge.svg?color=purple)](https://maven-badges.herokuapp.com/maven-central/com.password4j/password4j)
[![Java 8 or higher](https://img.shields.io/badge/JDK-8%2B-007396)](https://docs.oracle.com/javase/8/)
[![Android 5.0 or higher](https://img.shields.io/badge/Android-5.0%2B-3DDC84)](https://developer.android.com/about/versions/lollipop4)
[![Mentioned in Awesome Java](https://awesome.re/mentioned-badge.svg)](https://github.com/sindresorhus/awesome)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=alert_status)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=security_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=coverage)](https://sonarcloud.io/dashboard?id=Password4j_password4j)

Password4j is a Java **user-friendly** cryptographic library for encrypting and verifying passwords with different [Key derivation functions](https://en.wikipedia.org/wiki/Key_derivation_function) (KDFs) 
and [Cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (CHFs).

Algorithms can be configured **programmatically** or through a **property file** in your classpath <sup>see [Configuration section](#Configuration)</sup>.

The configurations are mostly dependent on your environment. Password4j delivers a **tool that can create
a set of optimal parameters** based on the system performance and the desired maximum computational time <sup>see [Performance section](#Performance)</sup>.

![Imgur](https://imgur.com/7xyROFH.png)


The library fully supports **[Argon2](https://en.wikipedia.org/wiki/Argon2)**, **[bcrypt](https://en.wikipedia.org/wiki/Bcrypt)**, **[scrypt](https://en.wikipedia.org/wiki/Scrypt)** and **[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)** 
and can produce and handle cryptographic **[salt](https://en.wikipedia.org/wiki/Salt_%28cryptography%29)** and **[pepper](https://en.wikipedia.org/wiki/Pepper_%28cryptography%29)**.

## Documentation
[![Wiki](https://img.shields.io/badge/wiki-available-brightgreen?logo=wikipedia&logoColor=white)](https://github.com/Password4j/password4j/wiki)
[![javadoc](https://javadoc.io/badge2/com.password4j/password4j/javadoc.svg)](https://javadoc.io/doc/com.password4j/password4j)


The full documentation can be found **[here](https://github.com/Password4j/password4j/wiki)**. For a quick start you can follow the instuctions in the `README.md`.

The javadoc can be found [here](https://javadoc.io/doc/com.password4j/password4j).


## Installation
Password4j runs on **Java 8 or higher versions** by any vendor. It is compatible with **Android API 21+** as well.

The artifacts are deployed to [Maven Central](https://search.maven.org/). 
Add the dependency of the latest version to your `pom.xml`:
```xml
<dependency>
    <groupId>com.password4j</groupId>
    <artifactId>password4j</artifactId>
    <version>1.6.2</version>
</dependency>
```



## Usage
Password4j provides three main features: password hashing, hash checking and hash updating.

### Hash the password
Here it is the easiest way to hash a password with a CHF (scrypt in this case). Salt and pepper may be optionally added to the builder: 

![Imgur](https://imgur.com/ZmOz5iB.png)

The same structure can be adopted for the other CHFs, not just for scrypt.


### Verify the hash
With the same ease you can verify the hash. Salt and pepper may be optionally added to the builder (Argon2 in this case): 

![Imgur](https://imgur.com/IGEPcU2.png)

 The same structure can be adopted for the other algorithms, not just for Argon2. Take in account that Argon2, bcrypt and scrypt store the salt
 inside the hash, so the `addSalt()` method is not needed.

 ![Imgur](https://imgur.com/xIwtpMo.png)


### Update the hash
When a configuration is not considered anymore secure  you can
refresh the hash with a more modern algorithm like this:

![Imgur](https://imgur.com/Yt31red.png)


Or if you want to switch from a CHF to another one:

![Imgur](https://imgur.com/CQYu6xj.png)



### List of supported algorithms
| Key derivation Functions | Since | Notes                                                |
|--------------------------|-------|------------------------------------------------------|
| PBKDF2                   | 1.0.0 | Depending on the Security Services your JVM provides |
| bcrypt                   | 1.0.0 |                                                      |
| scrypt                   | 1.0.0 |                                                      |
| Argon2                   | 1.5.0 |                                                      |

| Cryptographic Hash Functions | Since | Notes                                                 |
|------------------------------|-------|-------------------------------------------------------|
| MD Family                    | 1.4.0 |                                                       |
| SHA1 Family                  | 1.4.0 |                                                       |
| SHA2 Family                  | 1.4.0 |                                                       |
| SHA3 FAmily                  | 1.4.0 | Depending on the Security Providers your JVM provides |

### Unsecure Algorithms
Many systems may still use unsecure algorithms for storing the passwords, like [MD5](https://en.wikipedia.org/wiki/MD5) or [SHA-256](https://en.wikipedia.org/wiki/SHA-2).
You can easily migrate to stronger algorithms with Password4j

![Imgur](https://imgur.com/neS1m55.png)



## Configuration
Password4j makes available a portable way to configure the library.

With the property file `psw4j.properties` put in your classpath, you can define the parameters of all the supported CHFs or just the CHF(s) you need.
Alternatively you can specify a custom path with the system property `-Dpsw4j.configuration`

```shell script
java -Dpsw4j.configuration=/my/path/to/some.properties ...
```

Here's a basic configuration (please do not use it in production, but instead start a benchmark session in your target environment<sup>see [Performance section](#Performance)</sup>)
```properties
### Argon2
hash.argon2.memory=4096
hash.argon2.iterations=20
hash.argon2.length=128
hash.argon2.parallelism=4
hash.argon2.type=id


### bcrypt
hash.bcrypt.minor=b
# logarithmic cost (cost = 2^12)
hash.bcrypt.rounds=12


### scrypt
# N
hash.scrypt.workfactor=16384
# r
hash.scrypt.resources=16
# p
hash.scrypt.parallelization=1
# length
hash.scrypt.derivedKeyLength=64

### PBKDF2
# with HMAC-SHA256
hash.pbkdf2.algorithm=SHA256
# 64000 iterations
hash.pbkdf2.iterations=64000
# derived key of 256bit 
hash.pbkdf2.length=256


### Legacy MessageDisgest
# algorithm
hash.md.algorithm=SHA-512
# append/prepend salt
hash.md.salt.option=append
```
Additionally you can define here your shared pepper
```properties
global.pepper=AlicePepper
```
and use it like this
```java
// Hash
Password.hash("password").addPepper().withScrypt();

// Verify
Password.check("password", "hash").addPepper().withScrypt();
```

[SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) may be instantiated and used through `SecureRandom.getInstanceStrong()` to generate salts and peppers.
```properties
global.random.strong=true
```
but make sure that your JVM supports it and it points to a non-blocking source of entropy, otherwise you may experience huge performance drops<sup>see [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html#getInstanceStrong--)</sup>.

## Performance
<sup>This tool must be used in the target system because performances may vary on different environments.</sup>

Password4j is delivered with a tool that helps the developers to choose the right parameters for a specific CHF.

The class `SystemChecker` can be used to find these optimal values.

In the wiki you can find how to configure [PBKDF2](https://github.com/Password4j/password4j/wiki/Recommended-settings#responsiveness), [bcrypt](https://github.com/Password4j/password4j/wiki/Recommended-settings#responsiveness-1), [scrypt](https://github.com/Password4j/password4j/wiki/Recommended-settings#responsiveness-2) and [Argon2](https://github.com/Password4j/password4j/wiki/Recommended-settings#responsiveness-3) depending on your responsiveness requirements.

## JCA
Password4j is compatible with JCA. See [this project](https://github.com/Password4j/password4j-jca) for more details.


## Contributing
![GitHub issues](https://img.shields.io/github/issues/Password4j/password4j?color=success)
![GitHub closed issues](https://img.shields.io/github/issues-closed/Password4j/password4j)

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning
![SemVer 2.0.0](https://img.shields.io/badge/SemVer-2.0.0-orange)

We use [SemVer](http://semver.org/) for versioning. 

For the versions available, see the [releases on this repository](https://github.com/Password4j/password4j/releases). 

## Authors
![GitHub contributors](https://img.shields.io/github/contributors/Password4j/password4j)

* **David Bertoldi** - *Main Maintainer* - [firaja](https://github.com/firaja)

See also the list of [contributors](https://github.com/Password4j/password4j/contributors) who participated in this project.

## License
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This project is licensed under the Apache License 2.0 License - see the [LICENSE](LICENSE) file for details


## Changelog
![GitHub Release Date](https://img.shields.io/github/release-date/Password4j/password4j)

See the [CHANGELOG.md](CHANGELOG.md) file for a more detailed description of each release.
