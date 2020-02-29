package com.password4j;

import org.junit.Assert;
import org.junit.Test;


public class SaltGeneratorTest
{

    @Test
    public void testSaltLength()
    {
        // GIVEN
        int length = 23;

        // WHEN
        byte[] salt = SaltGenerator.generate(length);

        // THEN
        Assert.assertNotNull(salt);
        Assert.assertEquals(length, salt.length);
    }


    @Test
    public void testSaltNoLength()
    {
        // GIVEN

        // WHEN
        byte[] salt = SaltGenerator.generate();

        // THEN
        Assert.assertNotNull(salt);
        Assert.assertEquals(64, salt.length);
    }

    @Test(expected = BadParametersException.class)
    public void testSaltNegativeLength()
    {
        // GIVEN

        // WHEN
        byte[] salt = SaltGenerator.generate(-3);

        // THEN

    }

    @Test
    public void testSaltZeroLength()
    {
        // GIVEN
        int length = 0;

        // WHEN
        byte[] salt = SaltGenerator.generate(length);

        // THEN
        Assert.assertNotNull(salt);
        Assert.assertEquals(length, salt.length);
    }


}
