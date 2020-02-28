/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.password4j;

import org.junit.Assert;
import org.junit.Test;


public class PasswordTest
{

    @Test
    public void testCoherence()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";

        // WHEN
        Hash hash1 = Password.hash(password).addPepper(pepper).addSalt(salt).withPBKDF2();
        Hash hash2 = Password.hash(password).addPepper(pepper).withBCrypt();
        Hash hash3 = Password.hash(password).addPepper(pepper).addSalt(salt).withSCrypt();

        // THEN
        Assert.assertTrue(hash1.check(password));
        Assert.assertTrue(hash2.check(password));
        Assert.assertTrue(hash3.check(password));
    }


    @Test
    public void testRawCheck1()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";
        Hash hash = Password.hash(password).addPepper(pepper).addSalt(salt).withPBKDF2();
        String hashed = hash.getResult();

        // WHEN
        PBKDF2Function strategy = PBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(pepper + password, hashed));
        Assert.assertTrue(Password.check(hashed, password).addPepper(pepper).withPBKDF2());
    }

    @Test
    public void testRawCheck2()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";
        Hash hash = Password.hash(password).addPepper(pepper).withBCrypt();
        String hashed = hash.getResult();

        // WHEN
        BCryptFunction strategy = new BCryptFunction(12);

        // THEN
        Assert.assertTrue(strategy.check(pepper + password, hashed));
        Assert.assertTrue(Password.check(hashed, password).addPepper(pepper).withBCrypt());
    }

    @Test
    public void testRawCheck3()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";
        Hash hash = Password.hash(password).addPepper(pepper).addSalt(salt).withSCrypt();
        String hashed = hash.getResult();

        // WHEN
        SCryptFunction strategy = SCryptFunction.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(pepper + password, hashed));
        Assert.assertTrue(Password.check(hashed, password).addPepper(pepper).withSCrypt());
    }





}
