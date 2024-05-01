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


import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class Utils
{

    static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;
    static final int AVAILABLE_PROCESSORS = Runtime.getRuntime().availableProcessors();
    private static final char[] HEX_ALPHABET = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    private static final char[] TO_BASE64 = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
            '/'};
    private static final int[] FROM_BASE64 = new int[256];
    private static final AtomicInteger THREAD_COUNTER = new AtomicInteger(1);
    private static final Pattern STRONG_PATTERN = Pattern.compile("\\s*([\\S&&[^:,]]*)(\\:([\\S&&[^,]]*))?\\s*(\\,(.*))?");

    private static final ThreadGroup THREAD_GROUP = new ThreadGroup("Password4j Workers");

    static
    {
        Arrays.fill(FROM_BASE64, -1);
        for (int i = 0; i < TO_BASE64.length; i++)
        {
            FROM_BASE64[TO_BASE64[i]] = i;
        }
        FROM_BASE64['='] = -2;
    }

    private Utils()
    {
        //
    }

    static byte[] fromCharSequenceToBytes(CharSequence charSequence)
    {
        return fromCharSequenceToBytes(charSequence, DEFAULT_CHARSET);
    }

    static int[] fromStringToUnsignedInts(String charSequence)
    {
        byte[] byteArray = charSequence.getBytes(DEFAULT_CHARSET);
        int[] ints = new int[byteArray.length];
        for (int i = 0; i < ints.length; i++)
        {
            ints[i] = Byte.toUnsignedInt(byteArray[i]);
        }
        return ints;
    }

    static byte[] fromCharSequenceToBytes(CharSequence charSequence, Charset charset)
    {
        if (charSequence == null)
        {
            return new byte[0];
        }
        CharsetEncoder encoder = charset.newEncoder();
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

    static char[] fromBytesToChars(byte[] bytes)
    {
        return new String(bytes, DEFAULT_CHARSET).toCharArray();
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

    static byte[] append(byte[] byteArray1, byte[] byteArray2)
    {
        byte[] result = new byte[byteArray1.length + byteArray2.length];
        System.arraycopy(byteArray1, 0, result, 0, byteArray1.length);
        System.arraycopy(byteArray2, 0, result, byteArray1.length, byteArray2.length);
        return result;
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

    static BigInteger bytesToInt(byte[] bytes)
    {
        for (int i = 0; i < bytes.length / 2; i++)
        {
            byte temp = bytes[i];
            bytes[i] = bytes[bytes.length - i - 1];
            bytes[bytes.length - i - 1] = temp;
        }
        return new BigInteger(1, bytes);
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

    static byte[] intToLittleEndianBytes(int a, int length)
    {
        return ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN).putInt(a).array();
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

    static String fromBytesToString(byte[] input)
    {
        return new String(input, DEFAULT_CHARSET);
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

    static byte[] decodeBase64(String src)
    {
        return decodeBase64(src.getBytes(DEFAULT_CHARSET));
    }

    static String encodeBase64(byte[] src)
    {
        return encodeBase64(src, true);
    }

    static String encodeBase64(byte[] src, boolean padding)
    {
        byte[] encoded = encode(src, padding);
        return new String(encoded);
    }

    static byte[] decodeBase64(byte[] src)
    {
        byte[] dst = new byte[outLength(src, src.length)];
        int ret = decode(src, src.length, dst);
        if (ret != dst.length)
        {
            dst = Arrays.copyOf(dst, ret);
        }
        return dst;
    }

    static byte[] encode(byte[] src, boolean padding)
    {
        int len = outLength(src.length, padding);
        byte[] dst = new byte[len];
        int ret = encode(src, src.length, dst, padding);
        if (ret != dst.length)
        {
            return Arrays.copyOf(dst, ret);
        }
        return dst;
    }

    private static int outLength(int length, boolean doPadding)
    {
        int len;
        if (doPadding)
        {
            len = 4 * ((length + 2) / 3);
        }
        else
        {
            int n = length % 3;
            len = 4 * (length / 3) + (n == 0 ? 0 : n + 1);
        }
        return len;
    }

    private static int outLength(byte[] source, int length)
    {
        int paddings = 0;
        if (length == 0)
        {
            return 0;
        }
        if (length < 2)
        {
            throw new IllegalArgumentException("Input byte[] should at least have 2 bytes for base64 bytes");
        }

        if (source[length - 1] == '=')
        {
            paddings++;
            if (source[length - 2] == '=')
            {
                paddings++;
            }
        }

        if (paddings == 0 && (length & 0x3) != 0)
        {
            paddings = 4 - (length & 0x3);
        }
        return 3 * ((length + 3) / 4) - paddings;
    }

    private static int encode(byte[] src, int end, byte[] dst, boolean padding)
    {
        char[] base64 = TO_BASE64;
        int sp = 0;
        int length = (end) / 3 * 3;
        int dp = 0;
        while (sp < length)
        {
            int sl0 = sp + length;
            for (int sp0 = sp, dp0 = dp; sp0 < sl0; sp0 += 3, dp0 += 4)
            {
                int bits = (src[sp0] & 0xff) << 16 | (src[sp0 + 1] & 0xff) << 8 | (src[sp0 + 2] & 0xff);
                dst[dp0] = (byte) base64[(bits >>> 18) & 0x3f];
                dst[dp0 + 1] = (byte) base64[(bits >>> 12) & 0x3f];
                dst[dp0 + 2] = (byte) base64[(bits >>> 6) & 0x3f];
                dst[dp0 + 3] = (byte) base64[bits & 0x3f];
            }
            int dlen = (sl0 - sp) / 3 * 4;
            dp += dlen;
            sp = sl0;
        }
        if (sp < end)
        {
            int b0 = src[sp++] & 0xff;
            dst[dp++] = (byte) base64[b0 >> 2];
            if (sp == end)
            {
                dst[dp++] = (byte) base64[(b0 << 4) & 0x3f];
                if (padding)
                {
                    dst[dp++] = '=';
                    dst[dp++] = '=';
                }
            }
            else
            {
                int b1 = src[sp] & 0xff;
                dst[dp++] = (byte) base64[(b0 << 4) & 0x3f | (b1 >> 4)];
                dst[dp++] = (byte) base64[(b1 << 2) & 0x3f];
                if (padding)
                {
                    dst[dp++] = '=';
                }
            }
        }
        return dp;
    }

    private static int decode(byte[] src, int sl, byte[] dst)
    {
        int dp = 0;
        int bits = 0;
        int sp = 0;
        int shiftTo = 18;
        while (sp < sl)
        {
            int b = src[sp++] & 0xff;
            if ((b = FROM_BASE64[b]) < 0)
            {
                if (b == -2)
                {
                    if (shiftTo == 6 && (sp == sl || src[sp] != '=') || shiftTo == 18)
                    {
                        throw new IllegalArgumentException("Input byte array has wrong 4-byte ending unit");
                    }
                    break;
                }
                else
                    throw new IllegalArgumentException("Illegal base64 character " + Integer.toString(src[sp - 1], 16));
            }
            bits |= (b << shiftTo);
            shiftTo -= 6;
            if (shiftTo < 0)
            {
                dst[dp++] = (byte) (bits >> 16);
                dst[dp++] = (byte) (bits >> 8);
                dst[dp++] = (byte) (bits);
                shiftTo = 18;
                bits = 0;
            }
        }
        if (shiftTo == 6)
        {
            dst[dp++] = (byte) (bits >> 16);
        }
        else if (shiftTo == 0)
        {
            dst[dp++] = (byte) (bits >> 16);
            dst[dp++] = (byte) (bits >> 8);
        }
        else if (shiftTo == 12)
        {
            throw new IllegalArgumentException("Last unit does not have enough valid bits");
        }
        return dp;
    }

    @SuppressWarnings({"java:S1604"})
    static SecureRandom getInstanceStrong() throws NoSuchAlgorithmException
    {
        String property = AccessController.doPrivileged(new PrivilegedAction<String>()
        {
            @Override
            public String run()
            {
                return Security.getProperty("securerandom.strongAlgorithms");
            }
        });

        if ((property == null) || (property.isEmpty()))
        {
            throw new NoSuchAlgorithmException("Null/empty securerandom.strongAlgorithms Security Property");
        }

        String remainder = property;
        while (remainder != null)
        {
            Matcher m = STRONG_PATTERN.matcher(remainder);
            if (m.matches())
            {
                String alg = m.group(1);
                String prov = m.group(3);

                try
                {
                    if (prov == null)
                    {
                        return SecureRandom.getInstance(alg);
                    }
                    else
                    {
                        return SecureRandom.getInstance(alg, prov);
                    }
                }
                catch (NoSuchAlgorithmException | NoSuchProviderException e)
                {
                    //
                }
                remainder = m.group(5);
            }
            else
            {
                remainder = null;
            }
        }

        throw new NoSuchAlgorithmException("No strong SecureRandom impls available: " + property);
    }

    static String randomPrintable(int count)
    {
        Random random = AlgorithmFinder.getSecureRandom();

        StringBuilder builder = new StringBuilder(count);
        int start = 32;
        int gap = 126 - start;

        while (count-- != 0)
        {
            int codePoint = random.nextInt(gap) + start;
            builder.appendCodePoint(codePoint);
        }
        return builder.toString();
    }

    static void printBanner(PrintStream printStream)
    {
        if (PropertyReader.readBoolean("global.banner", false))
        {
            String pbkdf2Banner;
            List<String> pbkd2s = AlgorithmFinder.getAllPBKDF2Variants();
            if (!pbkd2s.isEmpty())
            {
                pbkdf2Banner = "✅ PBKDF2-" + String.join("/", pbkd2s).replace("PBKDF2WithHmac", "");
            }
            else
            {
                pbkdf2Banner = "❌ PBKDF2 <-- not supported by " + System.getProperty("java.vm.name");
            }

            String banner = "\n";
            banner += "    |\n" +
                    "    |                \033[0;1mPassword4j\033[0;0m\n" +
                    "    + \\             .: v1.8.2 :.\n" +
                    "    \\\\.G_.*=.\n" +
                    "     `(H'/.\\|        ✅ Argon2\n" +
                    "      .>' (_--.      ✅ scrypt\n" +
                    "   _=/d   ,^\\        ✅ bcrypt\n" +
                    " ~~ \\)-'-'           " + pbkdf2Banner + "\n" +
                    "    / |              ✅ balloon hashing\n" +
                    "    '  '";
            banner += "\n";
            banner += " ⭐ If you enjoy Password4j, please star the project at https://github.com/Password4j/password4j\n";
            banner += " \uD83E\uDEB2  Report any issue at https://github.com/Password4j/password4j/issues\n";

            printStream.println(banner);

        }
    }

    static List<byte[]> split(byte[] array, byte delimiter)
    {
        List<byte[]> byteArrays = new LinkedList<>();

        int begin = 0;

        for (int i = 0; i < array.length; i++)
        {

            if (array[i] != delimiter)
            {
                continue;
            }

            byteArrays.add(Arrays.copyOfRange(array, begin, i));
            begin = i + 1;
        }
        byteArrays.add(Arrays.copyOfRange(array, begin, array.length));
        return byteArrays;
    }

    static ExecutorService createExecutorService()
    {
        return Executors.newFixedThreadPool(AVAILABLE_PROCESSORS, runnable -> {
            Thread thread = new Thread(THREAD_GROUP, runnable, "password4j-worker-" + THREAD_COUNTER.getAndIncrement());
            thread.setDaemon(true);
            return thread;
        });
    }
}
