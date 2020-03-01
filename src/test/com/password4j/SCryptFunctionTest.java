package com.password4j;

import org.junit.Assert;
import org.junit.Test;


public class SCryptFunctionTest
{

    @Test(expected = BadParametersException.class)
    public void testBadHash()
    {
        // GIVEN
        String badHash = "bad$hash&";

        // WHEN
        SCryptFunction.getInstanceFromHash(badHash);

    }

    @Test(expected = BadParametersException.class)
    public void testNullPassword()
    {
        // GIVEN
        SCryptFunction scrypt = new SCryptFunction(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

        // WHEN
        scrypt.hash("password", "salt");

    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int r = 1;
        int N = 2;
        int p = 3;
        SCryptFunction scrypt = new SCryptFunction(r, N, p);

        // THEN
        boolean eqNull = scrypt.equals(null);
        boolean eqClass = scrypt.equals(new BCryptFunction());
        boolean difInst = scrypt.equals(new SCryptFunction(4, 5, 6));
        boolean sameInst = scrypt.equals(new SCryptFunction(r, N, p));

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
    }

    @Test
    public void testResources()
    {
        // GIVEN

        // WHEN
        SCryptFunction scrypt = new SCryptFunction(3, 5, 7);

        // THEN
        Assert.assertEquals(13_440, scrypt.getRequiredBytes());
    }

}
