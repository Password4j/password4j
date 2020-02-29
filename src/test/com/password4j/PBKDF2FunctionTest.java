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

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;


public class PBKDF2FunctionTest
{


    @Test
    public void testPBKDF2()
    {
        // GIVEN
        HashingFunction strategy = new CompressedPBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
        String password = "password";
        String salt = "abc";

        // WHEN
        Hash hash = strategy.hash(password, salt);

        // THEN
        Assert.assertEquals("$3$42949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=", hash.getResult());
    }

    @Test
    public void testPBKDF2EachVariants()
    {
        for(PBKDF2Function.Algorithm alg : PBKDF2Function.Algorithm.values())
        {
            // GIVEN
            HashingFunction strategy = new CompressedPBKDF2Function(alg.name(), 10_000, 256);
            String password = "password";
            String salt = "abc";

            // WHEN
            Hash hash = strategy.hash(password, salt);

            // THEN
            Assert.assertTrue(hash.getResult().startsWith("$"+alg.getCode()+"$"));
        }
    }

    @Test(expected = UnsupportedOperationException.class)
    public void testPBKDF2WrongAlgorithm()
    {
        // GIVEN
        HashingFunction strategy = new PBKDF2Function("notAnAlgorithm", 10_000, 256);
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
        HashingFunction strategy = new PBKDF2Function();
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
        HashingFunction strategy = new PBKDF2Function("notAnAlgorithm", 10_000, 256);
        String password = "password";
        String salt = new String(new byte[0]);

        // WHEN
        strategy.hash(password, salt);

        // THEN
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

    @Test
    public void testPBKDF2Coherence()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new PBKDF2Function().hash(password);

        // THEN
        Assert.assertTrue(hash.check(password));

    }

    @Test
    public void testPBKDF2CheckWithFixedConfigurations()
    {
        // GIVEN
        String hashed = "$3$42949672960256$YWJj$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=";
        String userSubmittedPassword = "password";

        // WHEN
        HashingFunction strategy = new CompressedPBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, hashed));
    }


    @Test
    public void testPBKDF2equality()
    {
        // GIVEN
        PBKDF2Function strategy1 = new PBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
        PBKDF2Function strategy2 = new PBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
        PBKDF2Function strategy3 = new PBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA1.name(), 10_000, 256);
        PBKDF2Function strategy4 = new PBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 64_000, 256);
        PBKDF2Function strategy5 = new PBKDF2Function(PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256.name(), 64_000, 123);



        // WHEN
        Map<PBKDF2Function, String> map =new HashMap<>();
        map.put(strategy1, strategy1.toString());
        map.put(strategy2, strategy2.toString());
        map.put(strategy3, strategy3.toString());
        map.put(strategy4, strategy4.toString());
        map.put(strategy5, strategy5.toString());



        // THEN
        Assert.assertEquals(4, map.size());
        Assert.assertEquals(strategy1, strategy2);
    }

}
