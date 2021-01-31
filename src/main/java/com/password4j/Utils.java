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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class Utils
{

    private static final char[] HEX_ALPHABET = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    private Utils()
    {
        //
    }

    static byte[] fromCharSequenceToBytes(CharSequence charSequence)
    {
        if (charSequence == null || charSequence.length() == 0)
        {
            return new byte[0];
        }
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(charSequence));
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());

        // clear sensitive data
        Arrays.fill(byteBuffer.array(), (byte) 0);
        return bytes;
    }

    static char[] fromCharSequenceToChars(CharSequence charSequence)
    {
        if (charSequence == null || charSequence.length() == 0)
        {
            return new char[0];
        }
        char[] result = new char[charSequence.length()];
        for (int i = 0; i < charSequence.length(); i++)
        {
            result[i] = charSequence.charAt(i);
        }
        return result;
    }

    static CharSequence append(CharSequence cs1, CharSequence cs2)
    {
        if (cs1 == null || cs1.length() == 0)
        {
            return cs2;
        }

        if (cs2 == null || cs2.length() == 0)
        {
            return cs1;
        }

        char[] charArray1 = fromCharSequenceToChars(cs1);
        char[] charArray2 = fromCharSequenceToChars(cs2);

        char[] result = new char[charArray1.length + charArray2.length];
        System.arraycopy(charArray1, 0, result, 0, charArray1.length);
        System.arraycopy(charArray2, 0, result, charArray1.length, charArray2.length);

        return new SecureString(result);

    }

    static String toHex(byte[] bytes)
    {
        final int length = bytes.length;
        final char[] output = new char[length << 1];
        int j = 0;
        for (byte aByte : bytes)
        {
            output[j++] = HEX_ALPHABET[(0xF0 & aByte) >>> 4];
            output[j++] = HEX_ALPHABET[0x0F & aByte];
        }
        return new String(output);
    }

    static long littleEndianToLong(byte[] bs, int off)
    {
        int lo = littleEndianToInt(bs, off);
        int hi = littleEndianToInt(bs, off + 4);
        return ((hi & 0xffffffffL) << 32) | (lo & 0xffffffffL);
    }

    static void littleEndianToInt(byte[] bs, int bOff, int[] ns, int nOff, int count)
    {
        for (int i = 0; i < count; ++i)
        {
            ns[nOff + i] = littleEndianToInt(bs, bOff);
            bOff += 4;
        }
    }

    static void littleEndianToInt(byte[] bs, int off, int[] ns)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToInt(bs, off);
            off += 4;
        }
    }

    static int littleEndianToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    static int[] littleEndianToInt(byte[] bs, int off, int count)
    {
        int[] ns = new int[count];
        for (int i = 0; i < ns.length; ++i)
        {
            ns[i] = littleEndianToInt(bs, off);
            off += 4;
        }
        return ns;
    }

    static byte[] longToLittleEndian(long n)
    {
        byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    static void longToLittleEndian(long n, byte[] bs, int off)
    {
        intToLittleEndian((int)(n & 0xffffffffL), bs, off);
        intToLittleEndian((int)(n >>> 32), bs, off + 4);
    }

    static void intToLittleEndian(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static byte[] intToLittleEndianBytes(int a) {
        byte[] result = new byte[4];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        return result;
    }

    public static long[] fromBytesToLongs(byte[] input) {
        long[] v = new long[128];
        for (int i = 0; i < v.length; i++) {
            byte[] slice = Arrays.copyOfRange(input, i * 8, (i + 1) * 8);
            v[i] = littleEndianBytesToLong(slice);
        }
        return v;
    }

    public static long littleEndianBytesToLong(byte[] b) {
        long result = 0;
        for (int i = 7; i >= 0; i--) {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

}
