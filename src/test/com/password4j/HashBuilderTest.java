package com.password4j;

import org.junit.Assert;
import org.junit.Test;

import java.awt.event.KeyEvent;


public class HashBuilderTest
{
    @Test
    public void testPrintable()
    {
        // GIVEN

        // WHEN
        Hash hash = Password.hash("a password").addRandomSalt().withCompressedPBKDF2();

        // THEN
        Assert.assertNotNull(hash.getSalt());
        Assert.assertTrue(isPrintableChar(hash.getResult()));
    }

    @Test
    public void testPrintable2()
    {
        // GIVEN

        // WHEN
        Hash hash = Password.hash("a password").withBcrypt();

        // THEN
        Assert.assertNotNull(hash.getSalt());
        Assert.assertTrue(isPrintableChar(hash.getResult()));
    }

    @Test
    public void testPrintable3()
    {
        // GIVEN

        // WHEN
        Hash hash = Password.hash("a password").addRandomSalt().withScrypt();

        // THEN
        Assert.assertNotNull(hash.getSalt());
        Assert.assertTrue(isPrintableChar(hash.getResult()));
    }

    private static boolean isPrintableChar(String str)
    {
        boolean res = true;
        for (char c : str.toCharArray())
        {
            Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
            res &= (!Character.isISOControl(
                    c)) && c != KeyEvent.CHAR_UNDEFINED && block != null && block != Character.UnicodeBlock.SPECIALS;
        }

        return res;
    }
}
