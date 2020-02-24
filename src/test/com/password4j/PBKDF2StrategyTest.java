package com.password4j;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;


public class PBKDF2StrategyTest
{


    @Test
    public void testPBKDF2()
    {
        // GIVEN
        HashingStrategy strategy = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
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
        for(PBKDF2Strategy.Algorithm alg : PBKDF2Strategy.Algorithm.values())
        {
            // GIVEN
            HashingStrategy strategy = new PBKDF2Strategy(alg.name(), 10_000, 256);
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
        HashingStrategy strategy = new PBKDF2Strategy("notAnAlgorithm", 10_000, 256);
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
        HashingStrategy strategy = new PBKDF2Strategy();
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
        HashingStrategy strategy = new PBKDF2Strategy("notAnAlgorithm", 10_000, 256);
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
        HashingStrategy strategy = PBKDF2Strategy.getInstanceFromHash(hashed);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, hashed));
    }

    @Test
    public void testPBKDF2Coherence()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new PBKDF2Strategy().hash(password);

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
        HashingStrategy strategy = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);

        // THEN
        Assert.assertTrue(strategy.check(userSubmittedPassword, hashed));
    }


    @Test
    public void testPBKDF2equality()
    {
        // GIVEN
        PBKDF2Strategy strategy1 = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
        PBKDF2Strategy strategy2 = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 10_000, 256);
        PBKDF2Strategy strategy3 = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA1.name(), 10_000, 256);
        PBKDF2Strategy strategy4 = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 64_000, 256);
        PBKDF2Strategy strategy5 = new PBKDF2Strategy(PBKDF2Strategy.Algorithm.PBKDF2WithHmacSHA256.name(), 64_000, 123);



        // WHEN
        Map<PBKDF2Strategy, String> map =new HashMap<>();
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
