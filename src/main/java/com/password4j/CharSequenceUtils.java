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

class CharSequenceUtils
{

    private static final char[] HEX_ALPHABET = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    private CharSequenceUtils()
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


}
