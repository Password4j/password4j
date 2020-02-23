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
        Assert.assertEquals("-4910ef00:abc:fd64d07d34dcf0783c1a5a653f42ed86981d125506f88dcccaebcaf0c2383274", hash.getResult());
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
