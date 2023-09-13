package com.password4j;

import com.password4j.types.Bcrypt;
import org.junit.Assert;
import org.junit.Test;

import java.util.Base64;
import java.util.Properties;

import static org.junit.Assert.assertEquals;


public class ScryptFunctionTest
{

    @Test(expected = BadParametersException.class)
    public void testBadHash()
    {
        // GIVEN
        String badHash = "bad$hash&";

        // WHEN
        ScryptFunction.getInstanceFromHash(badHash);

    }

    @Test(expected = BadParametersException.class)
    public void testNullPassword()
    {
        // GIVEN
        ScryptFunction scrypt = ScryptFunction.getInstance(Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE);

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
        Hash hash = new ScryptFunction(16384, 8, 1).hash(password, salt);
        String result = hash.getResult();
        byte[] bytes = hash.getBytes();

        // THEN
        String expected = "$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==";
        byte[] expectedBytes = Base64.getDecoder().decode(expected.split("\\$")[3]);
        Assert.assertEquals(expected, result);
        Assert.assertArrayEquals(expectedBytes, bytes);

    }

    @Test
    public void testHash2()
    {
        // GIVEN
        String password = "password";

        // WHEN
        boolean result = new ScryptFunction(16384, 8, 1)
                .check(password, "$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");

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
        boolean result = new ScryptFunction(16384, 8, 1).check(password, "$e0801$c2FsdA==$c2FsdA==");

        // THEN
        Assert.assertFalse(result);
    }

    @Test
    public void testHashRandomSalt()
    {
        // GIVEN
        String password = "password";
        ScryptFunction sCryptFunction = new ScryptFunction(16384, 8, 1);

        // WHEN
        Hash hash = sCryptFunction.hash(password);

        // THEN
        Assert.assertTrue(hash.getSalt() != null && hash.getSalt().length() > 0);
        Assert.assertEquals(sCryptFunction, ScryptFunction.getInstanceFromHash(hash.getResult()));
    }

    @Test
    public void testWrongCheck()
    {
        // GIVEN
        String password = "password";
        String salt = "salt";

        // WHEN
        Hash hash = new ScryptFunction(16384, 8, 1).hash(password, salt);

        // THEN
        Assert.assertFalse(hash.getHashingFunction().check(password, "$e0801$c2FsdA==$YXNkYXNkYXNkYXNk"));
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int r = 1;
        int N = 2;
        int p = 3;
        ScryptFunction scrypt = ScryptFunction.getInstance(N, r, p);

        // THEN
        boolean eqNull = scrypt.equals(null);
        boolean eqClass = scrypt.equals(new BcryptFunction(Bcrypt.A, 10));
        boolean difInst = scrypt.equals(ScryptFunction.getInstance(5, 4, 6));
        boolean sameInst = scrypt.equals(ScryptFunction.getInstance(N, r, p));
        boolean sameInst2 = scrypt.equals(new ScryptFunction(N, r, p));
        String toString = scrypt.toString();
        int hashCode = scrypt.hashCode();
        boolean notSameInst1 = scrypt.equals(new ScryptFunction(N + 1, r, p));
        boolean notSameInst2 = scrypt.equals(new ScryptFunction(N, r + 1 + 1, p));
        boolean notSameInst3 = scrypt.equals(new ScryptFunction(N, r, p + 1));

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
        Assert.assertTrue(sameInst2);
        Assert.assertNotEquals(toString, new ScryptFunction(5, 4, 6).toString());
        Assert.assertNotEquals(hashCode, new ScryptFunction(5, 4, 6).hashCode());
        Assert.assertFalse(notSameInst1);
        Assert.assertFalse(notSameInst2);
        Assert.assertFalse(notSameInst3);
    }

    @Test
    public void testResources()
    {
        // GIVEN

        // WHEN
        ScryptFunction scrypt1 = ScryptFunction.getInstance(5, 3, 7);
        ScryptFunction scrypt2 = ScryptFunction.getInstance(25, 30, 14);
        ScryptFunction scrypt3 = ScryptFunction.getInstance(1, 1, 1);

        // THEN
        Assert.assertEquals(13_440, scrypt1.getRequiredBytes());
        Assert.assertTrue(scrypt1.getRequiredMemory().indexOf("KB") > 0);
        Assert.assertEquals(1_344_000, scrypt2.getRequiredBytes());
        Assert.assertTrue(scrypt2.getRequiredMemory().indexOf("MB") > 0);
        Assert.assertEquals(128, scrypt3.getRequiredBytes());
        Assert.assertEquals("128B", scrypt3.getRequiredMemory());
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters1()
    {
        // GIVEN
        int r = 5;

        // WHEN
        ScryptFunction.getInstance((16777215 / r) + 1, r, 1).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters2()
    {
        // GIVEN
        int p = 5;

        // WHEN
        ScryptFunction.getInstance(16, (16777215 / p) + 1, p).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters3()
    {
        // GIVEN
        int k = 16777215;

        // WHEN
        ScryptFunction.getInstance(2, 2 << 20, 16777215).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters4()
    {
        // GIVEN

        // WHEN
        ScryptFunction.getInstance(1, 4, 3).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters5()
    {
        // GIVEN

        // WHEN
        ScryptFunction.getInstance(50, 4, 3).hash("password");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters6()
    {
        // GIVEN
        int p = 5;

        // WHEN
        new ScryptFunction(16384, 8, 1).check("password", "$s1$e0801$c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");
    }

    @Test(expected = BadParametersException.class)
    public void testBadParameters7()
    {
        // GIVEN

        // WHEN
        new ScryptFunction(16384, 8, 1).check("password", "$e0801c2FsdA==$dFcxr0SE8yOWiWntoomu7gBbWQOsVh5kpayhIXl793NO+f1YQi4uIhg7ysup7Ie6DIO3oueI8Dzg2gZGNDPNpg==");
    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        int workFactor = 3;
        int resources = 5;
        int parallelization = 7;
        int derivedKeyLength = 32;

        // WHEN
        ScryptFunction scrypt = ScryptFunction.getInstance(workFactor, resources, parallelization, derivedKeyLength);

        // THEN
        Assert.assertEquals(workFactor, scrypt.getWorkFactor());
        Assert.assertEquals(resources, scrypt.getResources());
        Assert.assertEquals(parallelization, scrypt.getParallelization());
        Assert.assertEquals(derivedKeyLength, scrypt.getDerivedKeyLength());
        Assert.assertEquals("ScryptFunction(N=3, r=5, p=7, l=32)", scrypt.toString());
    }

    @Test
    public void testOWASP()
    {
        // GIVEN
        Properties oldProps = PropertyReader.properties;
        PropertyReader.properties = null;

        // WHEN
        ScryptFunction scrypt = AlgorithmFinder.getScryptInstance();

        // THEN
        assertEquals(1 << 16, scrypt.getWorkFactor());
        assertEquals(8, scrypt.getResources());
        assertEquals(1, scrypt.getParallelization());
        assertEquals(ScryptFunction.DERIVED_KEY_LENGTH, scrypt.getDerivedKeyLength());

        PropertyReader.properties = oldProps;
    }



}
