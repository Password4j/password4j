/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.password4j;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

public class StringTest
{
    @Test
    public void testConstructors()
    {
        // GIVEN
        char[] password = new char[]{'a', 'b', 'c', 'd', 'e', 'f'};

        // WHEN
        SecureString ss = new SecureString(password);
        CharSequence sub1 = ss.subSequence(1, 4);
        SecureString sub2 = new SecureString(password, 1, 4);

        // THEN
        Assert.assertEquals(sub1.length(), sub2.length());
        Assert.assertEquals(Arrays.toString(new char[]{'b', 'c', 'd'}), Arrays.toString(Utilities.fromCharSequenceToChars(sub1)));
        Assert.assertEquals(Arrays.toString(Utilities.fromCharSequenceToChars(sub1)), Arrays.toString(Utilities.fromCharSequenceToChars(sub2)));

    }

    @Test
    public void testClear()
    {
        // GIVEN
        char[] password = new char[]{'a', 'b', 'c', 'd'};

        // WHEN
        SecureString ss = new SecureString(password);
        ss.clear();

        // THEN
        char z = Character.MIN_VALUE;
        Assert.assertEquals(Arrays.toString(new char[]{z, z, z, z}), Arrays.toString(Utilities.fromCharSequenceToChars(ss)));
    }

    @Test(expected = NullPointerException.class)
    public void testNull()
    {
       new SecureString(null);
    }

    @Test(expected = NullPointerException.class)
    public void testNull2()
    {
        new SecureString(null, 0, 0);
    }

    @Test(expected = ArrayIndexOutOfBoundsException.class)
    public void testOut1()
    {
        new SecureString(new char[]{'a', 'b', 'c', 'd'}, 0, 10);
    }

    @Test(expected = NegativeArraySizeException.class)
    public void testOut2()
    {
        new SecureString(new char[]{'a', 'b', 'c', 'd'}, 0, -4);
    }

    @Test(expected = NegativeArraySizeException.class)
    public void testOut3()
    {
        new SecureString(new char[]{'a', 'b', 'c', 'd'}, 3, 0);
    }

    @Test
    public void testEmpty()
    {
        SecureString ss = new SecureString(new char[0]);

        Assert.assertEquals("SecureString[]", ss.toString());
        Assert.assertEquals(0, ss.length());
        try
        {
            ss.charAt(0);
            Assert.fail();
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            Assert.assertTrue(true);
        }

    }

    @Test
    public void testToString()
    {
        SecureString ss = new SecureString(new char[]{'a', 'b', 'c', 'd'});

        Assert.assertEquals("SecureString[****]", ss.toString());
    }

    @Test
    public void erase()
    {
        // GIVEN
        char[] password1 = new char[]{'a', 'b', 'c', 'd'};
        char[] password2 = new char[]{'a', 'b', 'c', 'd'};

        // WHEN
        new SecureString(password1, true);
        new SecureString(password2, false);

        // THEN
        char z = Character.MIN_VALUE;
        Assert.assertEquals(Arrays.toString(new char[]{z, z, z, z}), Arrays.toString(password1));
        Assert.assertEquals(Arrays.toString(new char[]{'a', 'b', 'c', 'd'}), Arrays.toString(password2));
    }

    @Test
    public void testUtilities()
    {
        char[] c1 = Utilities.fromCharSequenceToChars(null);
        char[] c2 = Utilities.fromCharSequenceToChars(new String(new char[0]));
        byte[] b1 = Utilities.fromCharSequenceToBytes(null);
        byte[] b2 = Utilities.fromCharSequenceToBytes(new String(new char[0]));

        CharSequence cs1 = Utilities.append("a", null);
        CharSequence cs2 = Utilities.append(null, "b");

        CharSequence a1 = Utilities.append(new SecureString(new char[]{'a', 'b', 'c'}), "def");
        CharSequence a2 = Utilities.append(null, "def");
        CharSequence a3 = Utilities.append(new SecureString(new char[0]), "def");
        CharSequence a4 = Utilities.append("abc", null);
        CharSequence a5 = Utilities.append("abc", new SecureString(new char[0]));

        Assert.assertEquals(Arrays.toString(c1), Arrays.toString(c2));
        Assert.assertEquals(Arrays.toString(b1), Arrays.toString(b2));
        Assert.assertEquals("a", cs1);
        Assert.assertEquals("b", cs2);
        Assert.assertEquals(Arrays.toString(new char[]{'a', 'b', 'c', 'd', 'e', 'f'}), Arrays.toString(Utilities.fromCharSequenceToChars(a1)));
        Assert.assertEquals(Arrays.toString(new char[]{'d', 'e', 'f'}), Arrays.toString(Utilities.fromCharSequenceToChars(a2)));
        Assert.assertEquals(Arrays.toString(new char[]{'d', 'e', 'f'}), Arrays.toString(Utilities.fromCharSequenceToChars(a3)));
        Assert.assertEquals(Arrays.toString(new char[]{'a', 'b', 'c'}), Arrays.toString(Utilities.fromCharSequenceToChars(a4)));
        Assert.assertEquals(Arrays.toString(new char[]{'a', 'b', 'c'}), Arrays.toString(Utilities.fromCharSequenceToChars(a5)));
    }
}
