package org.password4j;

import org.junit.Assert;
import org.junit.Test;


public class HashStrategyTest
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
        Assert.assertEquals("$3$42949672960256$abc$/WTQfTTc8Hg8GlplP0LthpgdElUG+I3MyuvK8MI4MnQ=", hash.getResult());
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
}
