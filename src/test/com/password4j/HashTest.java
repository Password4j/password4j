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
        boolean result = hash.check(null);

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

        // THEN
        Assert.assertFalse(eq1);
        Assert.assertFalse(eq2);
        Assert.assertTrue(eq3);
        Assert.assertFalse(eq4);
        Assert.assertFalse(eq5);
        Assert.assertFalse(eq6);
    }

}
