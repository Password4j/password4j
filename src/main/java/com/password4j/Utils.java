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
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


class Utils
{

    static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

    private static final char[] HEX_ALPHABET = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    private Utils()
    {
        //
    }

    static byte[] fromCharSequenceToBytes(CharSequence charSequence)
    {
        if (charSequence == null)
        {
            return new byte[0];
        }
        CharsetEncoder encoder = DEFAULT_CHARSET.newEncoder();
        int length = charSequence.length();
        int arraySize = scale(length, encoder.maxBytesPerChar());
        byte[] result = new byte[arraySize];
        if (length == 0)
        {
            return result;
        }
        else
        {
            char[] charArray;
            if (charSequence instanceof String)
            {
                charArray = ((String) charSequence).toCharArray();
            }
            else
            {
                charArray = fromCharSequenceToChars(charSequence);
            }

            charArray = Arrays.copyOfRange(charArray, 0, length);

            encoder.onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE).reset();

            ByteBuffer byteBuffer = ByteBuffer.wrap(result);
            CharBuffer charBuffer = CharBuffer.wrap(charArray, 0, length);

            encoder.encode(charBuffer, byteBuffer, true);
            encoder.flush(byteBuffer);

            return Arrays.copyOf(result, byteBuffer.position());
        }

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

    static int littleEndianToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    static byte[] longToLittleEndian(long n)
    {
        byte[] bs = new byte[8];
        longToLittleEndian(n, bs, 0);
        return bs;
    }

    static void longToLittleEndian(long n, byte[] bs, int off)
    {
        intToLittleEndian((int) (n & 0xffffffffL), bs, off);
        intToLittleEndian((int) (n >>> 32), bs, off + 4);
    }

    static void intToLittleEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }

    static byte[] intToLittleEndianBytes(int a)
    {
        byte[] result = new byte[4];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        return result;
    }

    static long[] fromBytesToLongs(byte[] input)
    {
        long[] v = new long[128];
        for (int i = 0; i < v.length; i++)
        {
            byte[] slice = Arrays.copyOfRange(input, i * 8, (i + 1) * 8);
            v[i] = littleEndianBytesToLong(slice);
        }
        return v;
    }

    static long littleEndianBytesToLong(byte[] b)
    {
        long result = 0;
        for (int i = 7; i >= 0; i--)
        {
            result <<= 8;
            result |= (b[i] & 0xFF);
        }
        return result;
    }

    static byte[] longToLittleEndianBytes(long a)
    {
        byte[] result = new byte[8];
        result[0] = (byte) (a & 0xFF);
        result[1] = (byte) ((a >> 8) & 0xFF);
        result[2] = (byte) ((a >> 16) & 0xFF);
        result[3] = (byte) ((a >> 24) & 0xFF);
        result[4] = (byte) ((a >> 32) & 0xFF);
        result[5] = (byte) ((a >> 40) & 0xFF);
        result[6] = (byte) ((a >> 48) & 0xFF);
        result[7] = (byte) ((a >> 56) & 0xFF);
        return result;
    }

    static long intToLong(int x)
    {
        byte[] intBytes = intToLittleEndianBytes(x);
        byte[] bytes = new byte[8];
        System.arraycopy(intBytes, 0, bytes, 0, 4);
        return littleEndianBytesToLong(bytes);
    }

    static void xor(long[] t, long[] b1, long[] b2)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = b1[i] ^ b2[i];
        }
    }

    static void xor(long[] t, long[] b1, long[] b2, long[] b3)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = b1[i] ^ b2[i] ^ b3[i];
        }
    }

    static void xor(long[] t, long[] other)
    {
        for (int i = 0; i < t.length; i++)
        {
            t[i] = t[i] ^ other[i];
        }
    }

    static int log2(int number)
    {
        int log = 0;
        if ((number & -65536) != 0)
        {
            number >>>= 16;
            log = 16;
        }
        if (number >= 256)
        {
            number >>>= 8;
            log += 8;
        }
        if (number >= 16)
        {
            number >>>= 4;
            log += 4;
        }
        if (number >= 4)
        {
            number >>>= 2;
            log += 2;
        }
        return log + (number >>> 1);
    }

    private static int scale(int initialLength, float bytesPerChar)
    {
        return (int) ((double) initialLength * (double) bytesPerChar);
    }

}
