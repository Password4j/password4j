package com.password4j;

import org.junit.Assert;
import org.junit.Test;


public class PepperGeneratorTest
{

    @Test
    public void testSaltLength()
    {
        // GIVEN
        int length = 23;

        // WHEN
        String pepper = PepperGenerator.generate(length);

        // THEN
        Assert.assertNotNull(pepper);
        Assert.assertEquals(length, pepper.length());
    }


    @Test
    public void testSaltNoLength()
    {
        // GIVEN

        // WHEN
        String pepper = PepperGenerator.generate();

        // THEN
        Assert.assertNotNull(pepper);
        Assert.assertEquals(24, pepper.length());
    }

    @Test(expected = BadParametersException.class)
    public void testSaltNegativeLength()
    {
        // GIVEN

        // WHEN
        PepperGenerator.generate(-3);

        // THEN

    }

    @Test
    public void testSaltZeroLength()
    {
        // GIVEN
        int length = 0;

        // WHEN
        String pepper = PepperGenerator.generate(length);

        // THEN
        Assert.assertNotNull(pepper);
        Assert.assertEquals(length, pepper.length());
    }

    @Test
    public void testAlice()
    {
        // GIVEN

        // WHEN
        String pepper = PepperGenerator.get();

        // THEN
        Assert.assertEquals("AlicePepper", pepper);
    }
}
