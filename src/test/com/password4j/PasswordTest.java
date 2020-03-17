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

import java.security.SecureRandom;


public class PasswordTest
{

    private static final String PASSWORD = "password";
    private static final String SALT = "salt";
    private static final String PEPPER = "pepper";

    private static final SecureString SECURE_PASSWORD = new SecureString(PASSWORD.toCharArray());

    @Test
    public void testCoherence()
    {
        // GIVEN

        // WHEN
        Hash hash1 = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withPBKDF2();
        Hash hash2 = Password.hash(PASSWORD).addPepper(PEPPER).withBCrypt();
        Hash hash3 = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withSCrypt();

        // THEN
        Assert.assertTrue(Password.check(PASSWORD, hash1));
        Assert.assertTrue(Password.check(PASSWORD, hash2));
        Assert.assertTrue(Password.check(PASSWORD, hash3));
    }


    @Test
    public void testRawCheck1()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withCompressedPBKDF2();
        String hashed = hash.getResult();

        // WHEN
        PBKDF2Function strategy = CompressedPBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(PEPPER + PASSWORD, hashed));
        Assert.assertTrue(Password.check(PASSWORD, hashed).addPepper(PEPPER).withCompressedPBKDF2());
    }

    @Test
    public void testRawCheck2()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper(PEPPER).withBCrypt();
        String hashed = hash.getResult();

        // WHEN
        BCryptFunction strategy = new BCryptFunction(5);

        // THEN
        Assert.assertTrue(strategy.check(PEPPER + PASSWORD, hashed));
        Assert.assertTrue(Password.check(PASSWORD, hashed).addPepper(PEPPER).withBCrypt());
    }

    @Test
    public void testRawCheck3()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withSCrypt();
        String hashed = hash.getResult();

        // WHEN
        SCryptFunction strategy = SCryptFunction.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(PEPPER + PASSWORD, hashed));
        Assert.assertTrue(Password.check(PASSWORD, hashed).addPepper(PEPPER).withSCrypt());
    }

    @Test
    public void testCustomBuilder()
    {
        // GIVEN

        // WHEN
        Hash hash1 = Password.hash(PASSWORD, CustomHashBuilder::new).addPepper(PEPPER).addSalt(SALT).withTest();
        Hash hash2 = Password.hash(PASSWORD, CustomHashBuilder::new).addPepper(PEPPER).addSalt(SALT).withBCrypt();

        // THEN
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash1.getResult());
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash2.getResult());

    }

    @Test
    public void testMigration()
    {
        // GIVEN
        Hash oldHash = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withCompressedPBKDF2();

        // WHEN
        boolean oldCheck = Password.check(PASSWORD, oldHash.getResult()).addPepper(PEPPER).withCompressedPBKDF2();
        Hash newHash = Password.hash(PASSWORD).addSalt(PEPPER).withSCrypt();
        boolean newCheck = Password.check(PASSWORD, newHash.getResult()).withSCrypt();


        // THEN
        Assert.assertTrue(oldCheck);
        Assert.assertTrue(newCheck);

    }

    @Test
    public void testRandomSalt()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper(PEPPER).addRandomSalt(12).withCompressedPBKDF2();

        // WHEN
        boolean check1 = Password.check(PASSWORD, hash.getResult()).addPepper(PEPPER).withCompressedPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testCustomSalt()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper(PEPPER).addSalt(SALT).withPBKDF2();

        // WHEN
        boolean check1 = Password.check(PASSWORD, hash.getResult()).addPepper(PEPPER).addSalt(SALT).withPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testHashingFunction()
    {
        // GIVEN


        // WHEN
        Hash hash1 = Password.hash(PASSWORD).withPBKDF2();
        Hash hash2 = Password.hash(PASSWORD).withBCrypt();
        Hash hash3 = Password.hash(PASSWORD).withSCrypt();
        Hash hash4 = Password.hash(PASSWORD).withCompressedPBKDF2();


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
        Password.hash(PASSWORD, null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad3()
    {
        Password.check(null, (String)null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad4()
    {
        Password.check(null, PASSWORD);
    }

    @Test(expected = BadParametersException.class)
    public void testBad5()
    {
        Password.check(PASSWORD, PASSWORD, null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad6()
    {
        Password.hash(PASSWORD).addRandomSalt(-1);
    }

    @Test(expected = BadParametersException.class)
    public void testBad7()
    {
        Password.check(null, (Hash)null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad8()
    {
        Password.check(PASSWORD, new Hash(null, null, null));
    }

    @Test
    public void testConfigurablePepper()
    {
        // GIVEN
        Hash hash = Password.hash(PASSWORD).addPepper().withSCrypt();

        // WHEN
        boolean result = Password.check(PASSWORD, hash.getResult()).addPepper().withSCrypt();

        // THEN
        Assert.assertEquals(PropertyReader.readString("global.pepper", null, null), hash.getPepper());
        Assert.assertTrue(result);
    }

    @Test
    public void testSecureNeverNull() throws ClassNotFoundException
    {
        // GIVEN
        PropertyReader.PROPERTIES.put("global.random.strong", "true");

        // WHEN
        SecureRandom sr = AlgorithmFinder.getSecureRandom();

        // THEN
        Assert.assertNotNull(sr);

        PropertyReader.PROPERTIES.put("global.random.strong", "false");

    }

    @Test
    public void testCoherenceSecureString()
    {
        // GIVEN

        // WHEN
        Hash hash1 = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withPBKDF2();
        Hash hash2 = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).withBCrypt();
        Hash hash3 = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withSCrypt();

        // THEN
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hash1));
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hash2));
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hash3));
    }


    @Test
    public void testRawCheck1SecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withCompressedPBKDF2();
        String hashed = hash.getResult();

        // WHEN
        PBKDF2Function strategy = CompressedPBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(Utilities.append(PEPPER, SECURE_PASSWORD), hashed));
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hashed).addPepper(PEPPER).withCompressedPBKDF2());
    }

    @Test
    public void testRawCheck2SecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).withBCrypt();
        String hashed = hash.getResult();

        // WHEN
        BCryptFunction strategy = new BCryptFunction(5);

        // THEN
        Assert.assertTrue(strategy.check(Utilities.append(PEPPER, SECURE_PASSWORD), hashed));
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hashed).addPepper(PEPPER).withBCrypt());
    }

    @Test
    public void testRawCheck3SecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withSCrypt();
        String hashed = hash.getResult();

        // WHEN
        SCryptFunction strategy = SCryptFunction.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(Utilities.append(PEPPER, SECURE_PASSWORD), hashed));
        Assert.assertTrue(Password.check(SECURE_PASSWORD, hashed).addPepper(PEPPER).withSCrypt());
    }

    @Test
    public void testCustomBuilderSecureString()
    {
        // GIVEN

        // WHEN
        Hash hash1 = Password.hash(SECURE_PASSWORD, CustomHashBuilder::new).addPepper(PEPPER).addSalt(SALT).withTest();
        Hash hash2 = Password.hash(SECURE_PASSWORD, CustomHashBuilder::new).addPepper(PEPPER).addSalt(SALT).withBCrypt();

        // THEN
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash1.getResult());
        Assert.assertEquals(CustomHashBuilder.SAME_RESULT, hash2.getResult());

    }

    @Test
    public void testMigrationSecureString()
    {
        // GIVEN
        Hash oldHash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withCompressedPBKDF2();

        // WHEN
        boolean oldCheck = Password.check(SECURE_PASSWORD, oldHash.getResult()).addPepper(PEPPER).withCompressedPBKDF2();
        Hash newHash = Password.hash(SECURE_PASSWORD).addSalt(PEPPER).withSCrypt();
        boolean newCheck = Password.check(SECURE_PASSWORD, newHash.getResult()).withSCrypt();


        // THEN
        Assert.assertTrue(oldCheck);
        Assert.assertTrue(newCheck);

    }

    @Test
    public void testRandomSaltSecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addRandomSalt(12).withCompressedPBKDF2();

        // WHEN
        boolean check1 = Password.check(SECURE_PASSWORD, hash.getResult()).addPepper(PEPPER).withCompressedPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testCustomSaltSecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper(PEPPER).addSalt(SALT).withPBKDF2();

        // WHEN
        boolean check1 = Password.check(SECURE_PASSWORD, hash.getResult()).addPepper(PEPPER).addSalt(SALT).withPBKDF2();


        // THEN
        Assert.assertTrue(check1);
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
    }


    @Test
    public void testHashingFunctionSecureString()
    {
        // GIVEN


        // WHEN
        Hash hash1 = Password.hash(SECURE_PASSWORD).withPBKDF2();
        Hash hash2 = Password.hash(SECURE_PASSWORD).withBCrypt();
        Hash hash3 = Password.hash(SECURE_PASSWORD).withSCrypt();
        Hash hash4 = Password.hash(SECURE_PASSWORD).withCompressedPBKDF2();


        // THEN
        Assert.assertTrue(hash1.getHashingFunction() instanceof PBKDF2Function);
        Assert.assertTrue(hash2.getHashingFunction() instanceof BCryptFunction);
        Assert.assertTrue(hash3.getHashingFunction() instanceof SCryptFunction);
        Assert.assertTrue(hash4.getHashingFunction() instanceof CompressedPBKDF2Function);
    }



    @Test(expected = BadParametersException.class)
    public void testBad2SecureString()
    {
        Password.hash(SECURE_PASSWORD, null);
    }



    @Test(expected = BadParametersException.class)
    public void testBad5SecureString()
    {
        Password.check(SECURE_PASSWORD, PASSWORD, null);
    }

    @Test(expected = BadParametersException.class)
    public void testBad6SecureString()
    {
        Password.hash(SECURE_PASSWORD).addRandomSalt(-1);
    }


    @Test(expected = BadParametersException.class)
    public void testBad8SecureString()
    {
        Password.check(SECURE_PASSWORD, new Hash(null, null, null));
    }

    @Test
    public void testConfigurablePepperSecureString()
    {
        // GIVEN
        Hash hash = Password.hash(SECURE_PASSWORD).addPepper().withSCrypt();

        // WHEN
        boolean result = Password.check(SECURE_PASSWORD, hash.getResult()).addPepper().withSCrypt();

        // THEN
        Assert.assertEquals(PropertyReader.readString("global.pepper", null, null), hash.getPepper());
        Assert.assertTrue(result);
    }

    @Test
    public void testHashChecker()
    {
        // GIVEN
        HashChecker hc = new HashChecker(null, "hash");

        // WHEN
        boolean result = hc.with(AlgorithmFinder.getPBKDF2Instance());

        // THEN
        Assert.assertFalse(result);
    }

    @Test
    public void testHmac()
    {

        for(Hmac hmac : Hmac.values())
        {
            Assert.assertEquals("PBKDF2WithHmac" + hmac.name(), hmac.toString());
        }

    }

}
