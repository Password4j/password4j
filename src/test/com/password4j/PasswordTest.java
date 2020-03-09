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

import com.password4j.custom.CustomHashBuilder;
import org.apache.commons.lang3.StringUtils;
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
        System.out.println(hash2.getResult());
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
        Hash hash = Password.hash(password).addPepper(pepper).addSalt(salt).withCompressedPBKDF2();
        String hashed = hash.getResult();

        // WHEN
        PBKDF2Function strategy = CompressedPBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(pepper + password, hashed));
        Assert.assertTrue(Password.check(hashed, password).addPepper(pepper).withCompressedPBKDF2());
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
        BCryptFunction strategy = new BCryptFunction(5);

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

    @Test
    public void testCustomBuilder()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";

        // WHEN
        Hash hash1 = Password.hash(password, CustomHashBuilder::new).addPepper(pepper).addSalt(salt).withTest();
        Hash hash2 = Password.hash(password, CustomHashBuilder::new).addPepper(pepper).addSalt(salt).withBCrypt();

        // THEN
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash1.getResult());
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash2.getResult());

    }

    @Test
    public void testMigration()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";
        Hash oldHash = Password.hash(password).addPepper(pepper).addSalt(salt).withCompressedPBKDF2();

        // WHEN
        boolean oldCheck = Password.check(oldHash.getResult(), password).addPepper(pepper).withCompressedPBKDF2();
        Hash newHash = Password.hash(password).addSalt(pepper).withSCrypt();
        boolean newCheck = Password.check(newHash.getResult(), password).withSCrypt();


        // THEN
        Assert.assertTrue(oldCheck);
        Assert.assertTrue(newCheck);

    }

    @Test
    public void testRandomSalt()
    {
        // GIVEN
        String password = "password";
        String pepper = "pepper";
        Hash hash = Password.hash(password).addPepper(pepper).addRandomSalt(12).withCompressedPBKDF2();

        // WHEN
        boolean check1 = Password.check(hash.getResult(), password).addPepper(pepper).withCompressedPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testCustomSalt()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";
        String pepper = "pepper";
        Hash hash = Password.hash(password).addPepper(pepper).addSalt(salt).withPBKDF2();

        // WHEN
        boolean check1 = Password.check(hash.getResult(), password).addPepper(pepper).addSalt(salt).withPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testHashingFunction()
    {
        // GIVEN
        String password = "password";
        String pepper = "pepper";


        // WHEN
        Hash hash1 = Password.hash(password).withPBKDF2();
        Hash hash2 = Password.hash(password).withBCrypt();
        Hash hash3 = Password.hash(password).withSCrypt();
        Hash hash4 = Password.hash(password).withCompressedPBKDF2();


        // THEN
        Assert.assertTrue(hash1.getHashingFunction() instanceof PBKDF2Function);
        Assert.assertTrue(hash2.getHashingFunction() instanceof BCryptFunction);
        Assert.assertTrue(hash3.getHashingFunction() instanceof SCryptFunction);
        Assert.assertTrue(hash4.getHashingFunction() instanceof CompressedPBKDF2Function);
    }

    @Test(expected = BadParametersException.class)
    public void testBad1()
    {
        Password.hash(null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad2()
    {
        Password.hash("password", null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad3()
    {
        Password.check(null, null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad4()
    {
        Password.check("hash", null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad5()
    {
        Password.check("hash", "password", null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad6()
    {
        Password.hash("password").addRandomSalt(-1);
    }





}
