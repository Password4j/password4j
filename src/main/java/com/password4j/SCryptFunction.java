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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


public class SCryptFunction extends AbstractHashingFunction
{

    private int resources; // r

    private int workFactor; // N

    private int parallelization; // p

    private static ConcurrentMap<String, SCryptFunction> instances = new ConcurrentHashMap<>();

    private SCryptFunction()
    {
        //
    }

    protected SCryptFunction(int resources, int workFactor, int parallelization)
    {
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
    }

    public static SCryptFunction getInstanceFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            long params = Long.parseLong(parts[2], 16);
            int workFactor = (int) Math.pow(2.0D, (double) (params >> 16 & 65535L));
            int resources = (int) params >> 8 & 255;
            int parallelization = (int) params & 255;

            return SCryptFunction.getInstance(resources, workFactor, parallelization);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    public static SCryptFunction getInstance(int resources, int workFactor, int parallelization)
    {
        String key = getUID(resources, workFactor, parallelization);
        if (instances.containsKey(key))
        {
            return instances.get(key);
        }
        else
        {
            SCryptFunction function = new SCryptFunction(resources, workFactor, parallelization);
            instances.put(key, function);
            return function;
        }
    }

    @Override
    public Hash hash(String plain)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plain, new String(salt));
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        try
        {
            byte[] saltAsBytes = salt.getBytes(StandardCharsets.UTF_8);
            byte[] derived = scrypt(plain.getBytes(StandardCharsets.UTF_8), saltAsBytes, workFactor, resources, parallelization,
                    64);
            String params = Long.toString(log2(workFactor) << 16 | resources << 8 | parallelization, 16);
            String sb = "$s0$" + params + '$' + Base64.getEncoder().encodeToString(saltAsBytes) + '$' + Base64.getEncoder()
                    .encodeToString(derived);
            return new Hash(this, sb, salt);
        }
        catch (IllegalArgumentException | GeneralSecurityException e)
        {
            String message = "Invalid specification with salt=" + salt + ", N=`" + workFactor + ", r=`" + resources + " and p=`" + parallelization + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(String plain, String hashed)
    {
        try
        {
            String[] parts = hashed.split("\\$");
            if (parts.length == 5 && parts[1].equals("s0"))
            {
                long params = Long.parseLong(parts[2], 16);
                byte[] salt = Base64.getDecoder().decode(parts[3]);
                byte[] derived0 = Base64.getDecoder().decode(parts[4]);
                int n = (int) Math.pow(2.0D, (double) (params >> 16 & 65535L));
                int r = (int) params >> 8 & 255;
                int p = (int) params & 255;
                byte[] derived1 = scrypt(plain.getBytes(StandardCharsets.UTF_8), salt, n, r, p, 64);
                if (derived0.length != derived1.length)
                {
                    return false;
                }
                else
                {
                    int result = 0;

                    for (int i = 0; i < derived0.length; ++i)
                    {
                        result |= derived0[i] ^ derived1[i];
                    }

                    return result == 0;
                }
            }
            else
            {
                throw new BadParametersException("Invalid hashed value");
            }
        }
        catch (GeneralSecurityException var14)
        {
            throw new IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?");
        }
    }

    public long getRequiredBytes()
    {
        return 128L * workFactor * resources * parallelization;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        SCryptFunction otherStrategy = (SCryptFunction) obj;
        return this.workFactor == otherStrategy.workFactor //
                && this.resources == otherStrategy.resources //
                && this.parallelization == otherStrategy.parallelization;
    }

    @Override
    public String toString()
    {
        return getClass().getName() + '[' + getUID(this.resources, this.workFactor, this.parallelization) + ']';
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(resources, workFactor, parallelization);
    }

    protected static String getUID(int resources, int workFactor, int parallelization)
    {
        return String.valueOf(resources + '|' + workFactor + '|' + parallelization);
    }

    private static int log2(int n)
    {
        int log = 0;
        if ((n & -65536) != 0)
        {
            n >>>= 16;
            log = 16;
        }
        if (n >= 256)
        {
            n >>>= 8;
            log += 8;
        }
        if (n >= 16)
        {
            n >>>= 4;
            log += 4;
        }
        if (n >= 4)
        {
            n >>>= 2;
            log += 2;
        }
        return log + (n >>> 1);
    }

    public static byte[] scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen) throws GeneralSecurityException
    {
        if (N >= 2 && (N & N - 1) == 0)
        {
            if (N > 16777215 / r)
            {
                throw new IllegalArgumentException("Parameter N is too large");
            }
            else if (r > 16777215 / p)
            {
                throw new IllegalArgumentException("Parameter r is too large");
            }
            else
            {
                byte[] XY = new byte[256 * r];
                byte[] V = new byte[128 * r * N];
                byte[] B = PBKDF2Function
                        .internalHash(new String(passwd).toCharArray(), salt, PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256, 1,
                                8 * p * 128 * r).getEncoded();

                for (int i = 0; i < p; ++i)
                {
                    smix(B, i * 128 * r, r, N, V, XY);
                }

                return PBKDF2Function
                        .internalHash(new String(passwd).toCharArray(), B, PBKDF2Function.Algorithm.PBKDF2WithHmacSHA256, 1,
                                8 * dkLen).getEncoded();
            }
        }
        else
        {
            throw new IllegalArgumentException("N must be a power of 2 greater than 1");
        }
    }

    public static void smix(byte[] B, int Bi, int r, int N, byte[] V, byte[] XY)
    {
        int Xi = 0;
        int Yi = 128 * r;
        System.arraycopy(B, Bi, XY, Xi, 128 * r);

        int i;
        for (i = 0; i < N; ++i)
        {
            System.arraycopy(XY, Xi, V, i * 128 * r, 128 * r);
            blockmix_salsa8(XY, Xi, Yi, r);
        }

        for (i = 0; i < N; ++i)
        {
            int j = integerify(XY, Xi, r) & N - 1;
            blockxor(V, j * 128 * r, XY, Xi, 128 * r);
            blockmix_salsa8(XY, Xi, Yi, r);
        }

        System.arraycopy(XY, Xi, B, Bi, 128 * r);
    }

    public static void blockmix_salsa8(byte[] BY, int Bi, int Yi, int r)
    {
        byte[] X = new byte[64];
        System.arraycopy(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

        int i;
        for (i = 0; i < 2 * r; ++i)
        {
            blockxor(BY, i * 64, X, 0, 64);
            salsa20_8(X);
            System.arraycopy(X, 0, BY, Yi + i * 64, 64);
        }

        for (i = 0; i < r; ++i)
        {
            System.arraycopy(BY, Yi + i * 2 * 64, BY, Bi + i * 64, 64);
        }

        for (i = 0; i < r; ++i)
        {
            System.arraycopy(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
        }

    }

    public static int R(int a, int b)
    {
        return a << b | a >>> 32 - b;
    }

    public static void salsa20_8(byte[] B)
    {
        int[] B32 = new int[16];
        int[] x = new int[16];

        int i;
        for (i = 0; i < 16; ++i)
        {
            B32[i] = (B[i * 4] & 255);
            B32[i] |= (B[i * 4 + 1] & 255) << 8;
            B32[i] |= (B[i * 4 + 2] & 255) << 16;
            B32[i] |= (B[i * 4 + 3] & 255) << 24;
        }

        System.arraycopy(B32, 0, x, 0, 16);

        for (i = 8; i > 0; i -= 2)
        {
            x[4] ^= R(x[0] + x[12], 7);
            x[8] ^= R(x[4] + x[0], 9);
            x[12] ^= R(x[8] + x[4], 13);
            x[0] ^= R(x[12] + x[8], 18);
            x[9] ^= R(x[5] + x[1], 7);
            x[13] ^= R(x[9] + x[5], 9);
            x[1] ^= R(x[13] + x[9], 13);
            x[5] ^= R(x[1] + x[13], 18);
            x[14] ^= R(x[10] + x[6], 7);
            x[2] ^= R(x[14] + x[10], 9);
            x[6] ^= R(x[2] + x[14], 13);
            x[10] ^= R(x[6] + x[2], 18);
            x[3] ^= R(x[15] + x[11], 7);
            x[7] ^= R(x[3] + x[15], 9);
            x[11] ^= R(x[7] + x[3], 13);
            x[15] ^= R(x[11] + x[7], 18);
            x[1] ^= R(x[0] + x[3], 7);
            x[2] ^= R(x[1] + x[0], 9);
            x[3] ^= R(x[2] + x[1], 13);
            x[0] ^= R(x[3] + x[2], 18);
            x[6] ^= R(x[5] + x[4], 7);
            x[7] ^= R(x[6] + x[5], 9);
            x[4] ^= R(x[7] + x[6], 13);
            x[5] ^= R(x[4] + x[7], 18);
            x[11] ^= R(x[10] + x[9], 7);
            x[8] ^= R(x[11] + x[10], 9);
            x[9] ^= R(x[8] + x[11], 13);
            x[10] ^= R(x[9] + x[8], 18);
            x[12] ^= R(x[15] + x[14], 7);
            x[13] ^= R(x[12] + x[15], 9);
            x[14] ^= R(x[13] + x[12], 13);
            x[15] ^= R(x[14] + x[13], 18);
        }

        for (i = 0; i < 16; ++i)
        {
            B32[i] += x[i];
        }

        for (i = 0; i < 16; ++i)
        {
            B[i * 4] = (byte) (B32[i] & 255);
            B[i * 4 + 1] = (byte) (B32[i] >> 8 & 255);
            B[i * 4 + 2] = (byte) (B32[i] >> 16 & 255);
            B[i * 4 + 3] = (byte) (B32[i] >> 24 & 255);
        }

    }

    public static void blockxor(byte[] S, int Si, byte[] D, int Di, int len)
    {
        for (int i = 0; i < len; ++i)
        {
            D[Di + i] ^= S[Si + i];
        }

    }

    public static int integerify(byte[] B, int Bi, int r)
    {
        Bi += (2 * r - 1) * 64;
        int n = (B[Bi] & 255);
        n |= (B[Bi + 1] & 255) << 8;
        n |= (B[Bi + 2] & 255) << 16;
        n |= (B[Bi + 3] & 255) << 24;
        return n;
    }
}
