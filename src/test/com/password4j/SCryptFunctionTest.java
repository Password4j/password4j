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

}
