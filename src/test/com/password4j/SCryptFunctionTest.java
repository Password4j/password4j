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
    public void testHash1()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        Hash hash = new SCryptFunction(16384, 8, 1).hash(password, salt);

        // THEN
        Assert.assertEquals("$s0$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==", hash.getResult());

    }

    @Test
    public void testHash2()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        boolean result = new SCryptFunction(16384, 8, 1).check(password, "$s0$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");

        // THEN
        Assert.assertTrue(result);
    }

    @Test
    public void testHash3()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        boolean result = new SCryptFunction(16384, 8, 1).check(password, "$s0$e0801$c2FsdA==$c2FsdA==");

        // THEN
        Assert.assertFalse(result);
    }

    @Test
    public void testHashRandomSalt()
    {
        // GIVEN
        String password = "password";
        SCryptFunction sCryptFunction = new SCryptFunction(16384, 8, 1);

        // WHEN
        Hash hash = sCryptFunction.hash(password);

        // THEN
        Assert.assertTrue(StringUtils.isNotEmpty(hash.getSalt()));
        Assert.assertEquals(sCryptFunction, SCryptFunction.getInstanceFromHash(hash.getResult()));
    }

    @Test
    public void testWrongCheck()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        Hash hash = new SCryptFunction(16384, 8, 1).hash(password, salt);

        // THEN
        Assert.assertFalse(hash.getHashingFunction().check(password, "$s0$e0801$c2FsdA==$YXNkYXNkYXNkYXNk"));
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int r = 1;
        int N = 2;
        int p = 3;
        SCryptFunction scrypt = SCryptFunction.getInstance(N, r, p);

        // THEN
        boolean eqNull = scrypt.equals(null);
        boolean eqClass = scrypt.equals(new BCryptFunction(BCrypt.A,10));
        boolean difInst = scrypt.equals(SCryptFunction.getInstance(5, 4, 6));
        boolean sameInst = scrypt.equals(SCryptFunction.getInstance(N, r, p));
        String toString = scrypt.toString();
        int hashCode = scrypt.hashCode();

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
        Assert.assertNotEquals(toString, new SCryptFunction(5, 4, 6).toString());
        Assert.assertNotEquals(hashCode, new SCryptFunction(5, 4, 6).hashCode());
    }

    @Test
    public void testResources()
    {
        // GIVEN

        // WHEN
        SCryptFunction scrypt1 = SCryptFunction.getInstance(5, 3, 7);
        SCryptFunction scrypt2 = SCryptFunction.getInstance(25, 30, 14);
        SCryptFunction scrypt3 = SCryptFunction.getInstance(1, 1, 1);

        // THEN
        Assert.assertEquals(13_440, scrypt1.getRequiredBytes());
        Assert.assertTrue(StringUtils.contains(scrypt1.getRequiredMemory(), "KB"));
        Assert.assertEquals(1_344_000, scrypt2.getRequiredBytes());
        Assert.assertTrue(StringUtils.contains(scrypt2.getRequiredMemory(), "MB"));
        Assert.assertEquals(128, scrypt3.getRequiredBytes());
        Assert.assertEquals("128B", scrypt3.getRequiredMemory());
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters1()
    {
        // GIVEN
        int r = 5;

        // WHEN
        SCryptFunction.getInstance((16777215/r) + 1, r, 1).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters2()
    {
        // GIVEN
        int p = 5;

        // WHEN
        SCryptFunction.getInstance(16, (16777215/p) + 1, p).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters3()
    {
        // GIVEN
        int p = 5;

        // WHEN
        new SCryptFunction(16384, 8, 1).check("password", "$s1$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters4()
    {
        // GIVEN
        int p = 5;

        // WHEN
        new SCryptFunction(16384, 8, 1).check("password", "$s0e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");
    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        int workFactor = 3;
        int resources = 5;
        int parallelization = 7;

        // WHEN
        SCryptFunction scrypt = SCryptFunction.getInstance(workFactor, resources,parallelization);

        // THEN
        Assert.assertEquals(workFactor, scrypt.getWorkFactor());
        Assert.assertEquals(resources, scrypt.getResources());
        Assert.assertEquals(parallelization, scrypt.getParallelization());
        Assert.assertEquals("SCryptFunction[3|5|7]", scrypt.toString());
    }

}
