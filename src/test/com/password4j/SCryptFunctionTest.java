package com.password4j;

import org.apache.commons.lang3.StringUtils;
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
        SCryptFunction scrypt = SCryptFunction.getInstance(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

        // WHEN
        scrypt.hash("password", "salt");

    }

    @Test
    public void testHash()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        Hash hash = new SCryptFunction(8, 16384, 1).hash(password, salt);

        // THEN
        Assert.assertEquals("$s0$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==", hash.getResult());
    }

    @Test
    public void testHashRandomSalt()
    {
        // GIVEN
        String password = "password";
        SCryptFunction sCryptFunction = new SCryptFunction(8, 16384, 1);

        // WHEN
        Hash hash = sCryptFunction.hash(password);

        // THEN
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
        Assert.assertEquals(sCryptFunction, SCryptFunction.getInstanceFromHash(hash.getResult()));
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int r = 1;
        int N = 2;
        int p = 3;
        SCryptFunction scrypt = SCryptFunction.getInstance(r, N, p);

        // THEN
        boolean eqNull = scrypt.equals(null);
        boolean eqClass = scrypt.equals(new BCryptFunction(10));
        boolean difInst = scrypt.equals(SCryptFunction.getInstance(4, 5, 6));
        boolean sameInst = scrypt.equals(SCryptFunction.getInstance(r, N, p));
        String toString = scrypt.toString();
        int hashCode = scrypt.hashCode();

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
        Assert.assertNotEquals(toString, new SCryptFunction(4, 5, 6).toString());
        Assert.assertNotEquals(hashCode, new SCryptFunction(4, 5, 6).hashCode());
    }

    @Test
    public void testResources()
    {
        // GIVEN

        // WHEN
        SCryptFunction scrypt = SCryptFunction.getInstance(3, 5, 7);

        // THEN
        Assert.assertEquals(13_440, scrypt.getRequiredBytes());
    }

}
