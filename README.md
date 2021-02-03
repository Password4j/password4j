![logo](https://i.imgur.com/BAAwsxr.png "Password4j logo")

[![Build Status](https://travis-ci.org/Password4j/password4j.svg?branch=master)](https://travis-ci.org/Password4j/password4j)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.password4j/password4j/badge.svg?color=purple)](https://maven-badges.herokuapp.com/maven-central/com.password4j/password4j)
[![javadoc](https://javadoc.io/badge2/com.password4j/password4j/javadoc.svg)](https://javadoc.io/doc/com.password4j/password4j)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=alert_status)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=security_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=coverage)](https://sonarcloud.io/dashboard?id=Password4j_password4j)

Password4j is a Java **user-friendly** cryptographic library for hashing and checking passwords with different [Key derivation functions](https://en.wikipedia.org/wiki/Key_derivation_function) (KDFs) 
and [Cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (CHFs).

Algorithms can be configured **programmatically** or through a **property file** in your classpath <sup>see [Configuration section](#Configuration)</sup>.

The configurations are mostly dependent on your environment. Password4j delivers a **tool that can create
a set of optimal parameters** based on the system performance and the desired maximum computational time <sup>see [Performance section](#Performance)</sup>.

![Hash](https://i.imgur.com/1Pduapf.png)
![Verify](https://i.imgur.com/JgfNbQf.png)



The library fully supports **[Argon2](https://en.wikipedia.org/wiki/Argon2)**, **[BCrypt](https://en.wikipedia.org/wiki/Bcrypt)**, **[SCrypt](https://en.wikipedia.org/wiki/Scrypt)** and **[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)** 
and can produce and handle cryptographic **[salt](https://en.wikipedia.org/wiki/Salt_%28cryptography%29)** and **[pepper](https://en.wikipedia.org/wiki/Pepper_%28cryptography%29)**.


# Installation
Password4j runs on **Java 8**, **Java 9**, **Java 10** and **Java 11** by any vendor. It is supported by **Android API 26+** as well.

The artifacts are deployed to [Maven Central](https://search.maven.org/).
## ![Maven](https://i.imgur.com/2TZzobp.png?1) Maven 
Add the dependency of the latest version to your `pom.xml`:
```xml
<dependency>
    <groupId>com.password4j</groupId>
    <artifactId>password4j</artifactId>
    <version>1.5.0</version>
</dependency>
```

## ![Gradle](https://i.imgur.com/qtc6bXq.png?1) Gradle
Add to your `build.gradle` module dependencies:
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.password4j:password4j:1.5.0'
}
```

## ![Scala SBT](https://i.imgur.com/Nqv3mVd.png?1) Scala SBT 
Add to the managed dependencies of your `build.sbt` the latest version:
```shell script
libraryDependencies += "com.password4j" % "password4j" % "1.5.0"
```

# Usage
Password4j provides three main features: password hashing, hash checking and hash updating.

## Hash the password
Here it is the easiest way to hash a password with a CHF (BCrypt in this case)

```java
Hash hash = Password.hash(password).withBCrypt();
```

Salt and pepper may be optionally added to the builder (PBKDF2 in this case): 

```java
// PBKDF2 with salt 12 bytes long (randomly generated).
Hash hash = Password.hash(password).addRandomSalt(12).withPBKDF2();

// PBKDF2 with a chosen salt.
Hash hash = Password.hash(password).addSalt(salt).withPBKDF2();

// PBKDF2 with chosen salt and pepper.
Hash hash = Password.hash(password).addSalt(salt).addPepper(pepper).withPBKDF2();

// Custom PBKDF2 (PBKDF2 with HMAC-SHA512, 64000 iterations and 512bit length).
Hash hash = Password.hash(password).with(PBKDF2Function.getInstance(Hmac.SHA512, 64000, 512));

```
The same structure can be adopted for the other CHFs, not just for PBKDF2.


## Verify the hash
With the same ease you can verify the hash:
```java
boolean verified = Password.check(password, hash).withBCrypt();
```

Salt and pepper may be optionally added to the builder (PBKDF2 in this case): 

```java
// Verify with PBKDF2.
boolean verification = Password.check(password, hash).withPBKDF2();

// Verify with PBKDF2 and manually provided salt.
boolean verification = Password.check(password, hash).addSalt(salt).withPBKDF2();

// Verify with PBKDF2 and manually provided salt and pepper.
boolean verification = Password.check(password, hash).addSalt(salt).addPepper(pepper).withPBKDF2();
```
 The same structure can be adopted for the other algorithms, not just for PBKDF2. Take in account that Argon2, BCrypt and SCrypt store the salt
 inside the hash, so the `addSalt()` method is not needed.
```java
// Verify with Argon2, reads the salt from the given hash.
boolean verification = Password.check(password, hash).withArgon2();
```


## Update the hash
When a configuration is not considered anymore secure  you can
refresh the hash with a more modern algorithm like this:
```java
// Reads the latest configurations in your psw4j.properties
HashUpdate update = Password.check(password, hash).update().withBCrypt();

if(update.isVerified())
{
    Hash newHash = update.getHash();
}
```
Or if you want to switch from a CHF to another one:
```java
PBKDF2Function pbkdf2 = AlgorithmFinder.getPBKDF2Instance();
HashUpdate update = Password.check(password, hash).update().withSCrypt(pbkdf2);

if(update.isVerified())
{
    Hash newHash = update.getHash();
}
```

## Unsecure Algorithms
Many systems may still use unsecure algorithms for storing the passwords, like [MD5](https://en.wikipedia.org/wiki/MD5) or [SHA-256](https://en.wikipedia.org/wiki/SHA-2).
You can easily migrate to stronger algorithms with Password4j
```java
MessageDigestFunction md = MessageDigestFunction.getInstance("SHA-256");
HashUpdate update = Password.check(password, hash).update().withSCrypt(md);

if(update.isVerified())
{
    Hash newHash = update.getHash();
}
```

## List of supported algorithms
| Key derivation Functions | Since | Notes                                                |
|--------------------------|-------|------------------------------------------------------|
| PBKDF2                   | 1.0.0 | Depending on the Security Services your JVM provides |
| BCrypt                   | 1.0.0 |                                                      |
| SCrypt                   | 1.0.0 |                                                      |
| Argon2                   | 1.5.0 |                                                      |

| Cryptographic Hash Functions | Since | Notes                                                 |
|------------------------------|-------|-------------------------------------------------------|
| MD Family                    | 1.4.0 |                                                       |
| SHA1 Family                  | 1.4.0 |                                                       |
| SHA2 Family                  | 1.4.0 |                                                       |
| SHA3 FAmily                  | 1.4.0 | Depending on the Security Providers your JVM provides |


## Security of Strings
`String`s are immutable objects and once stored in memory you cannot erase them until Garbage Collection. It is always [recommended](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx) to use `char[]` instead of `String` for storing passwords<sup>(where possible - If we're talking of a web application, most web containers will pass the password into the `HttpServletRequest` object in plaintext as `String`)</sup>.

An attacker that is able to dump the memory could read the password before you use it as input for Password4j; even if it is read after its usage, it is not guaranteed when the garbage collection occurs: that means that the password may be stored in memory indefinitely and its value cannot be erased.

For this reason Password4j provides a `SecureString` class that **alleviates** this problem. The provided
`char[]` is wrapped around `SecureString` and it is never converted into a `String` during the process.

You can erase the underlying `char[]` with `clear()` method.
```java
SecureString secure = new SecureString(new char[]{...});

Password.hash(secure).withBCrypt();
Password.check(secure, hash).withBCrypt();

secure.clear();
// At this point the underlying char[] = {\0, \0, \0, ...}
```
In addition to this, you may want to clean the original `char[]`.
With the following code even the source is zeroed:
```java
char[] password = {...}
SecureString secure = new SecureString(password, true);

// At this point password = {\0, \0, \0, ...}
```
The pepper can be expressed as `SecureString` as well.

Using `SecureString` or `char[]` does not completely defend you from attacks: the Garbage Collector constantly copies objects from the _from space_ to the _to space_ and ereasing the original `char[]` does not erase its copies; moreover it is never guaranteed that `clear()` is applied before the garbage collection.
For these reasons the usage of `SecureString` or `char[]` just reduces the window of opportunities for an attacker.

# Configuration
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


### BCrypt
hash.bcrypt.minor=b
# logarithmic cost (cost = 2^12)
hash.bcrypt.rounds=12


### SCrypt
# N
hash.scrypt.workfactor=16384
# r
hash.scrypt.resources=16
# p
hash.scrypt.parallelization=1
hash.argon2.version=19


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
Password.hash("password").addPepper().withSCrypt();

// Verify
Password.check("password", "hash").addPepper().withSCrypt();
```

[SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) may be instantiated and used through `SecureRandom.getInstanceStrong()` to generate salts and peppers.
```properties
global.random.strong=true
```
but make sure that your JVM supports it and it points to a non-blocking source of entropy, otherwise you may experience huge performance drops<sup>see [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html#getInstanceStrong--)</sup>.

# Performance
<sup>This tool must be used in the target system because performances may vary on different environments.</sup>

Password4j is delivered with a tool that helps the developers to choose the right parameters for a specific CHF.

The class `SystemChecker` can be used to find these optimal values.

Here's an example on how to configure PBKDF2:
```java
Hmac algorithm = Hmac.SHA256;
int length = algorithm.bits();
long maxTimeInMilliseconds = 150;

int iterations  = SystemChecker.findIterationsForPBKDF2(maxTimeInMilliseconds, algorithm, length);

System.out.println("Iterations: " + iterations);
```

A similar approach can be used for BCrypt:
```java
long maxTimeInMilliseconds = 150;

int rounds = SystemChecker.findRoundsForBCrypt(maxTimeInMilliseconds);

System.out.println("Rounds: " + rounds);
```

And SCrypt:
```java
int r = 16;
int p = 1;
long maxTimeInMilliseconds = 150;

int N = SystemChecker.findWorkFactorForSCrypt(maxTimeInMilliseconds, r, p);
r = SystemChecker.findResourcesForSCrypt(maxTimeInMilliseconds, N, p);

System.out.println("N: " + N + ", r: " + r);
```


# Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

# Versioning
We use [SemVer](http://semver.org/) for versioning. 

For the versions available, see the [tags on this repository](https://github.com/Password4j/password4j/tags). 

# Authors

* **David Bertoldi** - *Initial work* - [firaja](https://github.com/firaja)

See also the list of [contributors](https://github.com/Password4j/password4j/contributors) who participated in this project.

# License

This project is licensed under the Apache License 2.0 License - see the [LICENSE](LICENSE) file for details


# Changelog

See the [CHANGELOG.md](CHANGELOG.md) file for a more detailed description of each release.
