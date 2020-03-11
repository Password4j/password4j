![logo](https://i.imgur.com/BAAwsxr.png "Password4j logo")

[![Build Status](https://travis-ci.org/Password4j/password4j.svg?branch=master)](https://travis-ci.org/Password4j/password4j)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=alert_status)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=security_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=Password4j_password4j&metric=coverage)](https://sonarcloud.io/dashboard?id=Password4j_password4j)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Password4j is a Java facade for hashing and checking passwords with different Crypto Hashing Functions (CHF) in
an easy and configurable way.

Algorithms can be configured **programmatically** or through a **property file** in your classpath <sup>(see Configuration section)</sup>.

The configurations are mostly dependent on your environment. Password4j delivers a **tool that can create
a set of optimal parameters** based on the system performance and the desired time threshold <sup>(see Performance section)</sup>.

![Hash and verify](https://i.imgur.com/zQMvGdG.png)

The library fully supports **BCrypt**, **SCrypt** and **PBKDF2** and can produce and handle cryptographic **salt** and **pepper**.


## Getting Started


You just need
 * **Java 1.8 +** by any vendor
 * **Maven 3.0 +**
 
### Installation

Put the following dependency in your `pom.xml` file.

```xml
<dependency>
    <groupId>com.password4j</groupId>
    <artifactId>password4j</artifactId>
    <version>0.4.0</version>
</dependency>
```

### Usage
Password4j provides two main methods to hash and verify passwords.

#### Password.*hash*()
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
Hash hash = Password.hash("password").with(new PBKDF2Function(Algorithm.SHA512, 64000, 512));
```
The same structure can be adopted for the other algorithms, not just for PBKDF2.

##### Customize Password.*hash*()
If you need to add a new method in the chain of parameters or want to override one, here's the fastest way:
```java
Password.hash("password", CustomBuilder::new).withSalt("fixed salt").withOtherStuff().withBCrypt();
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

#### Password.*check*()
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

### Configuration
Password4j makes available a portable way to configure the library.

With the property file `psw4j.properties` put in your classpath, you can define the parameters of all the supported CHFs or just the CHF(s) you need.

Here's a basic configuration (please do not use it in production, but instead start a benchmark session in your target environment<sup>(see Performance section)</sup>)
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

 ## Products successfully integrated with Password4j
 &nbsp;&nbsp;&nbsp;&nbsp;[![SAP Hybris Commerce Cloud](https://i.imgur.com/9eg6DP3.png "SAP Hybris Commerce Cloud")](https://www.sap.com/products/crm/e-commerce-platforms.html) &nbsp;&nbsp;&nbsp;&nbsp;
 &nbsp;&nbsp;&nbsp;&nbsp;[![Apereo CAS](https://i.imgur.com/88iYWwe.png "Apereo CAS")](https://www.apereo.org/projects/cas)




