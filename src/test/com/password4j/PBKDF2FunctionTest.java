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

import com.password4j.types.BCrypt;
import com.password4j.types.Hmac;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


public class PBKDF2FunctionTest
{


    @Test
    public void testPBKDF2()
    {
        // GIVEN
        HashingFunction function = CompressedPBKDF2Function.getInstance(Hmac.SHA256, 10_000, 256);
        String password = "password";
        String salt = "abc";

        // WHEN
        Hash hash = function.hash(password, salt);

        // THEN
        String result = "/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        Assert.assertEquals("$3$42949672960256$YWJj$" + result, hash.getResult());
        Assert.assertArrayEquals(Base64.getDecoder().decode(result), hash.getBytes());
    }

    @Test
    public void testPBKDF2EachVariants()
    {
        for (Hmac alg : Hmac.values())
        {
            // GIVEN
            HashingFunction strategy = CompressedPBKDF2Function.getInstance(alg, 10_000, 256);
            String password = "password";
            String salt = "abc";

            // WHEN
            Hash hash = strategy.hash(password, salt);

            // THEN
            Assert.assertTrue(hash.getResult().startsWith("$" + alg.code() + "$"));
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPBKDF2WrongAlgorithm()
    {
        // GIVEN
        HashingFunction strategy = PBKDF2Function.getInstance("notAnAlgorithm", 10_000, 256);
        String password = "password";
        String salt = "abc";

        // WHEN
        strategy.hash(password, salt);

        // THEN
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPBKDF2WrongAlgorithm2()
    {
        // GIVEN
        HashingFunction strategy = CompressedPBKDF2Function.getInstance("notAnAlgorithm", 10_000, 256);
        String password = "password";
        String salt = "abc";

        // WHEN
        strategy.hash(password, salt);

        // THEN
    }

    @Test(expected = BadParametersException.class)
    public void testPBKDF2WrongSalt()
    {
        // GIVEN
        HashingFunction strategy = PBKDF2Function.getInstance(Hmac.SHA224, 10_000, 224);
        String password = "password";
        String salt = new String(new byte[0]);

        // WHEN
        strategy.hash(password, salt);

        // THEN
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPBKDF2WrongAlgorithmSalt()
    {
        // GIVEN
        HashingFunction strategy = PBKDF2Function.getInstance("notAnAlgorithm", 10_000, 256);
        String password = "password";
        String salt = new String(new byte[0]);

        // WHEN
        strategy.hash(password, salt);

        // THEN
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPBKDF2WrongCheck()
    {
        // GIVEN
        HashingFunction strategy = AlgorithmFinder.getPBKDF2Instance();
        String password = "password";
        String salt = "salt";
        Hash hash = strategy.hash(password, salt);

        // WHEN
        strategy.check(password, hash.getResult());
    }

    @Test
    public void testPBKDF2Check()
    {
        // GIVEN
        String hashed = "$3$42949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String userSubmittedPassword = "password";

        // WHEN
        HashingFunction strategy = CompressedPBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, hashed));
    }


    @Test(expected = BadParametersException.class)
    public void testPBKDF2WrongCheck2()
    {
        // GIVEN
        String hashed = "$3$42949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String badHash = "$342949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String userSubmittedPassword = "password";

        // WHEN
        HashingFunction strategy = CompressedPBKDF2Function.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, badHash));
    }


    @Test(expected = BadParametersException.class)
    public void testPBKDF2BadCheck()
    {
        // GIVEN
        String hashed = "$342949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String userSubmittedPassword = "password";

        // WHEN
        CompressedPBKDF2Function.getInstanceFromHash(hashed);


    }

    @Test
    public void testAlgorithmFromCode()
    {
        // GIVEN

        // WHEN
        Hmac algNull = Hmac.fromCode(-100);
        for (Hmac enumAlg : Hmac.values())
        {
            Hmac alg = Hmac.fromCode(enumAlg.code());


            // THEN
            Assert.assertNotNull(alg);
            Assert.assertEquals(enumAlg.code(), alg.code());
            Assert.assertEquals(enumAlg.bits(), alg.bits());
        }
        Assert.assertNull(algNull);


    }

    @Test
    public void testPBKDF2Coherence()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = PBKDF2Function.getInstance(Hmac.SHA256, 8_777, 256).hash(password);

        // THEN
        Assert.assertTrue(Password.check(password, hash));

    }

    @Test
    public void testPBKDF2CheckWithFixedConfigurations()
    {
        // GIVEN
        String hashed = "$3$42949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String userSubmittedPassword = "password";

        // WHEN
        HashingFunction strategy = new CompressedPBKDF2Function(Hmac.SHA256, 10_000, 256);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, hashed));
    }


    @Test
    public void testPBKDF2equality()
    {
        // GIVEN
        PBKDF2Function strategy1 = PBKDF2Function.getInstance(Hmac.SHA256, 10_000, 256);
        PBKDF2Function strategy2 = PBKDF2Function.getInstance(Hmac.SHA256, 10_000, 256);
        PBKDF2Function strategy3 = PBKDF2Function.getInstance(Hmac.SHA1, 10_000, 256);
        PBKDF2Function strategy4 = PBKDF2Function.getInstance(Hmac.SHA256, 64_000, 256);
        PBKDF2Function strategy5 = PBKDF2Function.getInstance(Hmac.SHA256, 64_000, 123);


        // WHEN
        Map<PBKDF2Function, String> map = new HashMap<>();
        map.put(strategy1, strategy1.toString());
        map.put(strategy2, strategy2.toString());
        map.put(strategy3, strategy3.toString());
        map.put(strategy4, strategy4.toString());
        map.put(strategy5, strategy5.toString());


        // THEN
        Assert.assertEquals(4, map.size());
        Assert.assertEquals(strategy1, strategy2);
    }

    @Test
    public void testCompressed()
    {
        Hmac algorithm = Hmac.SHA512;


        for (int i = 1; i <= 100; i++)
        {
            String password = PepperGenerator.generate(12);
            String salt = PepperGenerator.generate(i);
            Hash hash = CompressedPBKDF2Function.getInstance(algorithm, 100 * i, algorithm.bits()).hash(password, salt);

            Hash notCompressedHash = PBKDF2Function.getInstance(algorithm, 100 * i, algorithm.bits()).hash(password, salt);

            String params = Long.toString((((long) 100 * i) << 32) | (algorithm.bits() & 0xffffffffL));
            String expected = "$" + algorithm.code() + "$" + params + "$" + Base64.getEncoder().encodeToString(salt.getBytes(Utils.DEFAULT_CHARSET)) + "$" + notCompressedHash.getResult();

            Assert.assertEquals(expected, hash.getResult());
            Assert.assertArrayEquals(hash.getBytes(), notCompressedHash.getBytes());
        }
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        Hmac hmac = Hmac.SHA256;
        int iterations = 2;
        int length = 256;
        PBKDF2Function pbkdf2Function = PBKDF2Function.getInstance(hmac, iterations, length);

        // THEN
        boolean eqNull = pbkdf2Function.equals(null);
        boolean eqClass = pbkdf2Function.equals(new BCryptFunction(BCrypt.A,10));
        boolean difInst = pbkdf2Function.equals(SCryptFunction.getInstance(5, 4, 6));
        boolean sameInst = pbkdf2Function.equals(PBKDF2Function.getInstance(hmac, iterations, length));
        boolean notSameInst1 = pbkdf2Function.equals(PBKDF2Function.getInstance(Hmac.SHA1, iterations, length));
        boolean notSameInst2 = pbkdf2Function.equals(PBKDF2Function.getInstance(hmac, iterations+1, length));
        boolean notSameInst3 = pbkdf2Function.equals(PBKDF2Function.getInstance(hmac, iterations, length*2));

        String toString = pbkdf2Function.toString();
        int hashCode = pbkdf2Function.hashCode();

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
        Assert.assertNotEquals(toString, new SCryptFunction(5, 4, 6).toString());
        Assert.assertNotEquals(hashCode, new SCryptFunction(5, 4, 6).hashCode());
        Assert.assertFalse(notSameInst1);
        Assert.assertFalse(notSameInst2);
        Assert.assertFalse(notSameInst3);

    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        Hmac hmac = Hmac.SHA384;
        int iterations = 5;
        int length = 7;

        // WHEN
        PBKDF2Function pbkdf2 = PBKDF2Function.getInstance(hmac, iterations, length);
        CompressedPBKDF2Function compressed = CompressedPBKDF2Function.getInstance(hmac, iterations, length);

        // THEN
        Assert.assertEquals(hmac.name(), pbkdf2.getAlgorithm());
        Assert.assertEquals(iterations, pbkdf2.getIterations());
        Assert.assertEquals(length, pbkdf2.getLength());
        Assert.assertEquals("PBKDF2Function[SHA384|5|7]", pbkdf2.toString());
        Assert.assertEquals("CompressedPBKDF2Function[SHA384|5|7]", compressed.toString());
    }

}
