package com.password4j;

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;


public class HashTest
{



    @Test
    public void testHashContent()
    {
        // GIVEN
        String hashed = "myHash";
        String salt = "mySalt";
        String pepper = "myPepper";
        HashingFunction function = new CompressedPBKDF2Function();

        // WHEN
        Hash hash = new Hash(function, hashed, salt);
        hash.setPepper(pepper);
        Hash hash2 = new Hash(function, hashed, salt);

        // THEN
        Assert.assertEquals(hashed, hash.getResult());
        Assert.assertEquals(salt, hash.getSalt());
        Assert.assertEquals(pepper, hash.getPepper());
        Assert.assertNull(hash2.getPepper());
    }

    @Test
    public void testHashCheckNull()
    {
        // GIVEN
        Hash hash = Password.hash("myPassword").withCompressedPBKDF2();

        // WHEN
        boolean result = Password.check(null, hash);

        // THEN
        Assert.assertFalse(result);
    }

    @Test
    public void testHashEquality()
    {
        // GIVEN
        Hash hash = Password.hash("myPassword").withCompressedPBKDF2();

        // WHEN
        boolean eq1 = hash.equals(null);
        boolean eq2 = hash.equals(new Object());
        boolean eq3 = hash.equals(new Hash(AlgorithmFinder.getCompressedPBKDF2Instance(), hash.getResult(), hash.getSalt()));
        boolean eq4 = hash.equals(new Hash(AlgorithmFinder.getPBKDF2Instance(), hash.getResult(), hash.getSalt()));
        boolean eq5 = hash.equals(new Hash(AlgorithmFinder.getCompressedPBKDF2Instance(), "hash", hash.getSalt()));
        boolean eq6 = hash.equals(new Hash(AlgorithmFinder.getCompressedPBKDF2Instance(), hash.getResult(), "salt"));

        hash.setPepper("pepper");
        Hash testingHash = new Hash(AlgorithmFinder.getCompressedPBKDF2Instance(), hash.getResult(), hash.getSalt());
        testingHash.setPepper(hash.getPepper());
        boolean eq7 = hash.equals(testingHash);
        hash.setPepper("reppep");
        boolean eq8 = hash.equals(testingHash);

        // THEN
        Assert.assertFalse(eq1);
        Assert.assertFalse(eq2);
        Assert.assertTrue(eq3);
        Assert.assertFalse(eq4);
        Assert.assertFalse(eq5);
        Assert.assertFalse(eq6);
        Assert.assertTrue(eq7);
        Assert.assertFalse(eq8);
    }

    @Test
    public void testSecFunc()
    {
        // GIVEN
        Hash hash1 = Password.hash("myPassword").withCompressedPBKDF2();
        Hash hash2 = Password.hash("myPassword").withPBKDF2();
        Hash hash3 = Password.hash("myPassword").addPepper().withPBKDF2();

        // WHEN
        String toString1 = hash1.toString();
        int hc1 = hash1.hashCode();
        String toString2 = hash2.toString();
        int hc2 = hash2.hashCode();
        String toString3 = hash3.toString();

        // THEN
        Assert.assertNotNull(toString1);
        Assert.assertNotNull(toString2);
        Assert.assertNotEquals(toString1, toString2);
        Assert.assertNotEquals(toString3, toString2);
        Assert.assertNotEquals(hc1, hc2);
    }

}
