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

import com.password4j.types.Hmac;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


/**
 * Class containing the implementation of scrypt function and its parameters.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Scrypt">scrypt</a>
 * @since 0.1.0
 */
public class ScryptFunction extends AbstractHashingFunction
{
    public static final int DERIVED_KEY_LENGTH = 64;

    private static final ConcurrentMap<String, ScryptFunction> INSTANCES = new ConcurrentHashMap<>();

    private int workFactor; // N

    private int resources; // r

    private int parallelization; // p

    private int derivedKeyLength; // dkLen

    @SuppressWarnings("unused")
    private ScryptFunction()
    {
        //
    }

    /**
     * @param workFactor      (N)
     * @param resources       (r)
     * @param parallelization (p)
     */
    protected ScryptFunction(int workFactor, int resources, int parallelization)
    {
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
        this.derivedKeyLength = DERIVED_KEY_LENGTH;
    }

    /**
     * @param workFactor       (N)
     * @param resources        (r)
     * @param parallelization  (p)
     * @param derivedKeyLength (dkLen)
     */
    protected ScryptFunction(int workFactor, int resources, int parallelization, int derivedKeyLength)
    {
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
        this.derivedKeyLength = derivedKeyLength;
    }

    /**
     * Reads the configuration contained in the given hash and
     * builds a singleton instance based on these configurations.
     *
     * @param hashed an already hashed password
     * @return a singleton instance based on the given hash
     * @since 1.0.0
     */
    public static ScryptFunction getInstanceFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 4)
        {
            long params = Long.parseLong(parts[1], 16);
            int workFactor = (int) Math.pow(2.0D, (params >> 16 & 65535L));
            int resources = (int) params >> 8 & 255;
            int parallelization = (int) params & 255;
            int derivedKeyLength = Utils.decodeBase64(parts[3]).length;

            return ScryptFunction.getInstance(workFactor, resources, parallelization, derivedKeyLength);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    /**
     * Creates a singleton instance, depending on the provided
     * N, r and p parameters.
     *
     * @param workFactor      work factor (N)
     * @param resources       resources (r)
     * @param parallelization parallelization (p)
     * @return a singleton instance
     * @since 0.3.0
     */
    public static ScryptFunction getInstance(int workFactor, int resources, int parallelization)
    {
        return getInstance(workFactor, resources, parallelization, DERIVED_KEY_LENGTH);
    }

    /**
     * Creates a singleton instance, depending on the provided
     * N, r and p parameters.
     *
     * @param workFactor       work factor (N)
     * @param resources        resources (r)
     * @param parallelization  parallelization (p)
     * @param derivedKeyLength derived key length (dkLen)
     * @return a singleton instance
     * @since 1.5.1
     */
    public static ScryptFunction getInstance(int workFactor, int resources, int parallelization, int derivedKeyLength)
    {
        String key = getUID(resources, workFactor, parallelization, derivedKeyLength);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            ScryptFunction function = new ScryptFunction(workFactor, resources, parallelization, derivedKeyLength);
            INSTANCES.put(key, function);
            return function;
        }
    }

    protected static String toString(int resources, int workFactor, int parallelization, int derivedKeyLength)
    {
        return "N=" + workFactor + ", r=" + resources + ", p=" + parallelization + ", l=" + derivedKeyLength;
    }

    protected static String getUID(int resources, int workFactor, int parallelization, int derivedKeyLength)
    {
        return workFactor + "|" + resources + "|" + parallelization + "|" + derivedKeyLength;
    }

    public static int rOperation(int a, int b)
    {
        return a << b | a >>> 32 - b;
    }

    public static void salsa208(byte[] xArray)
    {
        int[] b32 = new int[16];
        int[] x = new int[16];

        int i;
        for (i = 0; i < 16; ++i)
        {
            b32[i] = (xArray[i * 4] & 255);
            b32[i] |= (xArray[i * 4 + 1] & 255) << 8;
            b32[i] |= (xArray[i * 4 + 2] & 255) << 16;
            b32[i] |= (xArray[i * 4 + 3] & 255) << 24;
        }

        System.arraycopy(b32, 0, x, 0, 16);

        for (i = 8; i > 0; i -= 2)
        {
            x[4] ^= rOperation(x[0] + x[12], 7);
            x[8] ^= rOperation(x[4] + x[0], 9);
            x[12] ^= rOperation(x[8] + x[4], 13);
            x[0] ^= rOperation(x[12] + x[8], 18);
            x[9] ^= rOperation(x[5] + x[1], 7);
            x[13] ^= rOperation(x[9] + x[5], 9);
            x[1] ^= rOperation(x[13] + x[9], 13);
            x[5] ^= rOperation(x[1] + x[13], 18);
            x[14] ^= rOperation(x[10] + x[6], 7);
            x[2] ^= rOperation(x[14] + x[10], 9);
            x[6] ^= rOperation(x[2] + x[14], 13);
            x[10] ^= rOperation(x[6] + x[2], 18);
            x[3] ^= rOperation(x[15] + x[11], 7);
            x[7] ^= rOperation(x[3] + x[15], 9);
            x[11] ^= rOperation(x[7] + x[3], 13);
            x[15] ^= rOperation(x[11] + x[7], 18);
            x[1] ^= rOperation(x[0] + x[3], 7);
            x[2] ^= rOperation(x[1] + x[0], 9);
            x[3] ^= rOperation(x[2] + x[1], 13);
            x[0] ^= rOperation(x[3] + x[2], 18);
            x[6] ^= rOperation(x[5] + x[4], 7);
            x[7] ^= rOperation(x[6] + x[5], 9);
            x[4] ^= rOperation(x[7] + x[6], 13);
            x[5] ^= rOperation(x[4] + x[7], 18);
            x[11] ^= rOperation(x[10] + x[9], 7);
            x[8] ^= rOperation(x[11] + x[10], 9);
            x[9] ^= rOperation(x[8] + x[11], 13);
            x[10] ^= rOperation(x[9] + x[8], 18);
            x[12] ^= rOperation(x[15] + x[14], 7);
            x[13] ^= rOperation(x[12] + x[15], 9);
            x[14] ^= rOperation(x[13] + x[12], 13);
            x[15] ^= rOperation(x[14] + x[13], 18);
        }

        for (i = 0; i < 16; ++i)
        {
            b32[i] += x[i];
        }

        for (i = 0; i < 16; ++i)
        {
            xArray[i * 4] = (byte) (b32[i] & 255);
            xArray[i * 4 + 1] = (byte) (b32[i] >> 8 & 255);
            xArray[i * 4 + 2] = (byte) (b32[i] >> 16 & 255);
            xArray[i * 4 + 3] = (byte) (b32[i] >> 24 & 255);
        }

    }

    public static void blockXOR(byte[] sArray, int si, byte[] dArray, int di, int length)
    {
        for (int i = 0; i < length; ++i)
        {
            dArray[di + i] ^= sArray[si + i];
        }

    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        byte[] salt = SaltGenerator.generate();
        return internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), salt);
    }

    @Override
    public Hash hash(byte[] plainTextPasswordAsBytes)
    {
        byte[] salt = SaltGenerator.generate();
        return internalHash(plainTextPasswordAsBytes, salt);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        byte[] saltAsBytes = Utils.fromCharSequenceToBytes(salt);
        byte[] plainTextPasswordAsBytes = Utils.fromCharSequenceToBytes(plainTextPassword);
        return internalHash(plainTextPasswordAsBytes, saltAsBytes);
    }

    @Override
    public Hash hash(byte[] plainTextPasswordAsBytes, byte[] salt)
    {
        return internalHash(plainTextPasswordAsBytes, salt);
    }

    private Hash internalHash(byte[] plainTextPassword, byte[] salt)
    {

        try
        {
            byte[] derived = scrypt(plainTextPassword, salt, derivedKeyLength);
            String params = Long.toString((long) Utils.log2(workFactor) << 16 | (long) resources << 8 | parallelization, 16);
            String sb = "$" + params + '$' + Utils.encodeBase64(salt) + '$'
                    + Utils.encodeBase64(derived);
            return new Hash(this, sb, derived, salt);
        }
        catch (IllegalArgumentException | GeneralSecurityException e)
        {
            String stringedSalt = Utils.fromBytesToString(salt);
            String message = "Invalid specification with salt=" + stringedSalt + ", N=" + workFactor + ", r=" + resources + " and p=" + parallelization;
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(hashed));
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed)
    {
        try
        {
            List<byte[]> parts = Utils.split(hashed, (byte) 36);
            if (parts.size() == 4)
            {
                byte[] salt = Utils.decodeBase64(parts.get(2));
                byte[] derived0 = Utils.decodeBase64(parts.get(3));
                byte[] derived1 = scrypt(plainTextPassword, salt, derivedKeyLength);
                return slowEquals(derived0, derived1);
            }
            else
            {
                throw new BadParametersException("Invalid hashed value");
            }
        }
        catch (GeneralSecurityException gse)
        {
            throw new IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?", gse);
        }
    }

    /**
     * Estimates the required memory to calculate an hash with
     * the current configuration.
     *
     * @return the required memory
     * @since 0.1.0
     */
    public long getRequiredBytes()
    {
        return 128L * workFactor * resources * parallelization;
    }

    public int getWorkFactor()
    {
        return workFactor;
    }

    public int getResources()
    {
        return resources;
    }

    public int getParallelization()
    {
        return parallelization;
    }

    public int getDerivedKeyLength()
    {
        return derivedKeyLength;
    }

    /**
     * A more readable version of {@link #getRequiredBytes()},
     * changing the unit (B, KB, MB) so that the number has at most
     * 2 decimal places.
     *
     * @return the required memory
     * @since 0.3.0
     */
    public String getRequiredMemory()
    {
        long memoryInBytes = getRequiredBytes();
        if (memoryInBytes > 1_000_000)
        {
            return Math.round(memoryInBytes / 10_000f) / 100.0 + "MB";
        }
        if (memoryInBytes > 1_000)
        {
            return Math.round(memoryInBytes / 1_000f) / 100.0 + "KB";
        }
        return memoryInBytes + "B";
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        ScryptFunction otherStrategy = (ScryptFunction) obj;
        return this.workFactor == otherStrategy.workFactor //
                && this.resources == otherStrategy.resources //
                && this.parallelization == otherStrategy.parallelization;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '(' + toString(this.resources, this.workFactor, this.parallelization,
                this.derivedKeyLength) + ')';
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(resources, workFactor, parallelization);
    }

    public byte[] scrypt(byte[] passwd, byte[] salt, int dkLen) throws GeneralSecurityException
    {
        if (workFactor >= 2 && (workFactor & workFactor - 1) == 0)
        {
            if (workFactor > 16777215 / resources)
            {
                throw new IllegalArgumentException("Parameter N is too large");
            }
            else if (resources > 16777215 / parallelization)
            {
                throw new IllegalArgumentException("Parameter r is too large");
            }
            else
            {
                byte[] xyArray = new byte[256 * resources];
                byte[] vArray = new byte[128 * resources * workFactor];
                byte[] intensiveSalt = PBKDF2Function.internalHash(Utils.fromBytesToString(passwd).toCharArray(), salt, Hmac.SHA256.name(), 1,
                        8 * parallelization * 128 * resources).getEncoded();

                for (int i = 0; i < parallelization; ++i)
                {
                    sMix(intensiveSalt, i * 128 * resources, vArray, xyArray);
                }

                return PBKDF2Function
                        .internalHash(Utils.fromBytesToString(passwd).toCharArray(), intensiveSalt, Hmac.SHA256.name(), 1, 8 * dkLen)
                        .getEncoded();
            }
        }
        else
        {
            throw new IllegalArgumentException("N must be a power of 2 greater than 1. Found " + workFactor);
        }
    }

    public void sMix(byte[] intensiveSalt, int bi, byte[] vArray, byte[] xyArray)
    {
        int xi = 0;
        int yi = 128 * resources;
        System.arraycopy(intensiveSalt, bi, xyArray, xi, 128 * resources);

        int i;
        for (i = 0; i < workFactor; ++i)
        {
            System.arraycopy(xyArray, xi, vArray, i * 128 * resources, 128 * resources);
            blockmixSalsa8(xyArray, xi, yi);
        }

        for (i = 0; i < workFactor; ++i)
        {
            int j = integerify(xyArray, xi) & workFactor - 1;
            blockXOR(vArray, j * 128 * resources, xyArray, xi, 128 * resources);
            blockmixSalsa8(xyArray, xi, yi);
        }

        System.arraycopy(xyArray, xi, intensiveSalt, bi, 128 * resources);
    }

    public void blockmixSalsa8(byte[] xyArray, int bi, int yi)
    {
        byte[] xArray = new byte[64];
        System.arraycopy(xyArray, bi + (2 * resources - 1) * 64, xArray, 0, 64);

        int i;
        for (i = 0; i < 2 * resources; ++i)
        {
            blockXOR(xyArray, i * 64, xArray, 0, 64);
            salsa208(xArray);
            System.arraycopy(xArray, 0, xyArray, yi + i * 64, 64);
        }

        for (i = 0; i < resources; ++i)
        {
            System.arraycopy(xyArray, yi + i * 2 * 64, xyArray, bi + i * 64, 64);
        }

        for (i = 0; i < resources; ++i)
        {
            System.arraycopy(xyArray, yi + (i * 2 + 1) * 64, xyArray, bi + (i + resources) * 64, 64);
        }

    }

    public int integerify(byte[] xyArray, int xi)
    {
        xi += (2 * resources - 1) * 64;
        int n = (xyArray[xi] & 255);
        n |= (xyArray[xi + 1] & 255) << 8;
        n |= (xyArray[xi + 2] & 255) << 16;
        n |= (xyArray[xi + 3] & 255) << 24;
        return n;
    }
}
