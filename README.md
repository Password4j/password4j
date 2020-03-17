![logo](https://i.imgur.com/BAAwsxr.png "Password4j logo")

[![Build Status](https://travis-ci.org/Password4j/password4j.svg?branch=master)](https://travis-ci.org/Password4j/password4j)
[![Maven Central](https://img.shields.io/maven-central/v/com.password4j/password4j)](https://search.maven.org/artifact/com.password4j/password4j/1.2.0/jar)
[![javadoc](https://javadoc.io/badge2/com.password4j/password4j/javadoc.svg)](https://javadoc.io/doc/com.password4j/password4j)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=alert_status)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=security_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=coverage)](https://sonarcloud.io/dashboard?id=Password4j_password4j)

Password4j is a Java facade for hashing and checking passwords with different [Crypto Hashing Functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (CHF) in
an easy and configurable way.

Algorithms can be configured **programmatically** or through a **property file** in your classpath <sup>see [Configuration section](#Configuration)</sup>.

The configurations are mostly dependent on your environment. Password4j delivers a **tool that can create
a set of optimal parameters** based on the system performance and the desired time threshold <sup>see [Performance section](#Performance)</sup>.

![Hash and verify](https://i.imgur.com/zQMvGdG.png)

The library fully supports **[BCrypt](https://en.wikipedia.org/wiki/Bcrypt)**, **[SCrypt](https://en.wikipedia.org/wiki/Scrypt)** and **[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)** 
and can produce and handle cryptographic **[salt](https://en.wikipedia.org/wiki/Salt_(cryptography))** and **[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))**.


## Installation
Password4j runs on **Java 8** and **Java 12** of any vendor. It is supported by **Android API 26+** as well.

The artifacts are deployed to [Maven Central](https://search.maven.org/).
### ![Maven](https://i.imgur.com/2TZzobp.png?1) Maven 
Add the dependency of the latest version to your `pom.xml`:
```xml
<dependency>
    <groupId>com.password4j</groupId>
    <artifactId>password4j</artifactId>
    <version>1.2.1</version>
</dependency>
```

### ![Gradle](https://i.imgur.com/qtc6bXq.png?1) Gradle
Add to your `build.gradle` module dependencies:
```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation 'com.password4j:password4j:1.2.1'
}
```

### ![Scala SBT](https://i.imgur.com/Nqv3mVd.png?1) Scala SBT 
Add to the managed dependencies of your `build.sbt` the latest version:
```shell script
libraryDependencies += "com.password4j" % "password4j" % "1.2.1"
```

## Usage
Password4j provides two main methods to hash and verify passwords.

### Password.*hash*()
This method helps the developer to build a chain of parameters that the CHF will use to produce the hash.

Salt and pepper may be optionally added into the chain.

Example with PBKDF2: 
```java
// PBKDF2 with salt 12 bytes long (randomly generated).
Hash hash = Password.hash("password").addRandomSalt(12).withPBKDF2();

// PBKDF2 with a chosen salt.
Hash hash = Password.hash("password").addSalt("fixed salt").withPBKDF2();

// PBKDF2 with chosen salt and pepper.
Hash hash = Password.hash("password").addSalt("fixed salt").addPepper("pepper").withPBKDF2();

// Custom PBKDF2 (PBKDF2 with HMAC-SHA512, 64000 iterations and 512bit length).
Hash hash = Password.hash("password").with(PBKDF2Function.getInstance(Hmac.SHA512, 64000, 512));

```
The same structure can be adopted for the other algorithms, not just for PBKDF2.

#### Customize Password.*hash*()
If you need to add a new method in the chain of parameters or want to override one, here's the fastest way:
```java
Password.hash("password", CustomBuilder::new).addSalt("fixed salt").withOtherStuff().withBCrypt();
```
```java
public class CustomBuilder extends HashBuilder<CustomBuilder> {
    
    public CustomBuilder withOtherStuff() {
        // do here your stuff
        return this;
    }

    @Override
    public Hash withBCrypt() {
        return with(new MyBCryptVariant());               // Recommended way.
    }                                                     // It must implement HashingFunction
}
```
Create your custom `HashBuilder` and use it in `Password.hash()`.

### Password.*check*()
The verification process builds a chain of parameters, as well.
```java
String plaintext = "...";                                       // User provided password.
String hash = "...";                                            // Hash retrieved from DB for that user.

// Verify with PBKDF2.
boolean verification = Password.check(plaintext, hash).withPBKDF2();

// Verify with PBKDF2 and manually provided salt.
boolean verification = Password.check(plaintext, hash).addSalt("salt from db").withPBKDF2();

// Verify with PBKDF2 and manually provided salt and pepper.
boolean verification = Password.check(plaintext, hash).addSalt("salt from db").addPepper("pepper").withPBKDF2();
```
 The same structure can be adopted for the other algorithms, not just for PBKDF2. Take in account that BCrypt and SCrypt store the salt
 inside the hash, so that the `addSalt()` method is not needed.

##### Customize Password.*check*()
If you need to add a new method in the chain of parameters or want to override one, here's the fastest way:
```java
Password.check("password", "hash", CustomChecker::new).withOtherStuff().withBCrypt();
```
```java
public class CustomChecker extends HashChecker<CustomChecker> {
    
    public CustomChecker withOtherStuff() {
        // do here your stuff
        return this;
    }

    @Override
    public boolean withBCrypt() {
        return with(new MyBCryptVariant());               // Recommended way.
    }                                                     // It must implement HashingFunction
}
```
Create your custom `HashChecker` and use it in `Password.check()`.

### Security of Strings
`String`s are immutable objects and they are stored in the String Pool, a location in the heap memory.
Since you do not have control on the Garbage Collector, an attacker that has access to the memory could read the password
just before you use it as input for Password4j. Even after this, the `String` may be still persisted in memory
until the garbage collection occurs.

It is always recommended to use `char[]` instead of `String` <sup>(where possible - If we're talking of a web application, 
most web containers will pass the password into the `HttpServletRequest` object in plaintext as `String`)</sup>.

For this reason Password4j provides a `SecureString` class that alleviates this problem. The provided

You can erase the underlying `char[]` with `clear()` method.
```java
SecureString secure = new SecureString(new char[]{...});

Passowrd.hash(secure).withBCrypt();
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

## Configuration
Password4j makes available a portable way to configure the library.

With the property file `psw4j.properties` put in your classpath, you can define the parameters of all the supported CHFs or just the CHF(s) you need.

Here's a basic configuration (please do not use it in production, but instead start a benchmark session in your target environment<sup>see [Performance section](#Performance)</sup>)
```properties
### PBKDF2
# with HMAC-SHA256
hash.pbkdf2.algorithm=SHA256
# 64000 iterations
hash.pbkdf2.iterations=64000
# derived key of 256bit 
hash.pbkdf2.length=256

### BCrypt
# logarithmic cost (cost = 2^12)
hash.bcrypt.rounds=12

### SCrypt
# N
hash.scrypt.workfactor=16384
# r
hash.scrypt.resources=16
# p
hash.scrypt.parallelization=1
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

[SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html) may be instantiated through `SecureRandom.getInstanceStrong()`
```properties
global.random.strong=true
```
but make sure that your JVM supports it and it points to a non-blocking source of entropy, otherwise you may experience huge performance drops<sup>see [SecureRandom](https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html#getInstanceStrong--)</sup>.

## Performance
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


## Contributing
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning
We use [SemVer](http://semver.org/) for versioning. 

For the versions available, see the [tags on this repository](https://github.com/Password4j/password4j/tags). 

## Authors

* **David Bertoldi** - *Initial work* - [firaja](https://github.com/firaja)

See also the list of [contributors](https://github.com/Password4j/password4j/contributors) who participated in this project.

## License

This project is licensed under the Apache License 2.0 License - see the [LICENSE](LICENSE) file for details


## Changelog

See the [CHANGELOG.md](CHANGELOG.md) file for a more detailed description of each release.
