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
```java
// Validating the password with SCrypt
String hash = "$s0$e0801$c2FsdA==$dFcxr0SE8yOWiWnto..."
String userSubmittedPassword = "..."

Password.check(userSubmittedPassword, hash)   
        .addPepper("pepper")
        .withSCrypt();                           // SCrypt parameters are located
                                                 // in a property file
```

The library fully supports **BCrypt**, **SCrypt** and **PBKDF2** and can produce and handle cryptographic **salt** and **pepper**.


## Getting Started

### Prerequisites
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

 
 ## Products successfully integrated with Password4j
 &nbsp;&nbsp;&nbsp;&nbsp;[![SAP Hybris Commerce Cloud](https://i.imgur.com/9eg6DP3.png "SAP Hybris Commerce Cloud")](https://www.sap.com/products/crm/e-commerce-platforms.html) &nbsp;&nbsp;&nbsp;&nbsp;
 &nbsp;&nbsp;&nbsp;&nbsp;[![Apereo CAS](https://i.imgur.com/88iYWwe.png "Apereo CAS")](https://www.apereo.org/projects/cas)




