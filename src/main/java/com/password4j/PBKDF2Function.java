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

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public final class PBKDF2Function implements HashingFunction
{
    public static final Algorithm DEFAULT_ALGORITHM = Algorithm.PBKDF2WithHmacSHA512;

    public static final int DEFAULT_ITERATIONS = 64_000;

    public static final int DEFAULT_LENGTH = DEFAULT_ALGORITHM.bits;

    private Algorithm algorithm = DEFAULT_ALGORITHM;

    private int iterations = DEFAULT_ITERATIONS;

    private int length = DEFAULT_LENGTH;

    public static PBKDF2Function getInstanceFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            int algorithm = Integer.parseInt(parts[1]);
            long configuration = Long.parseLong(parts[2]);

            int iterations = (int) (configuration >> 32);
            int length = (int) configuration;

            return new PBKDF2Function(Algorithm.fromCode(algorithm), iterations, length);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    public PBKDF2Function()
    {
        //
    }

    public PBKDF2Function(int iterations, int length)
    {
        this();
        this.iterations = iterations;
        this.length = length;
    }

    public PBKDF2Function(String algorithm, int iterations, int length)
    {
        this(iterations, length);
        try
        {
            this.algorithm = Algorithm.valueOf(algorithm);
        }
        catch (IllegalArgumentException iae)
        {
            throw new UnsupportedOperationException("Algorithm `" + algorithm + "` is not recognized.", iae);
        }
    }

    public PBKDF2Function(Algorithm algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithm = algorithm;
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
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm.name());
            PBEKeySpec spec = new PBEKeySpec(plain.toCharArray(), salt.getBytes(), iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            String params = Long.toString((((long) iterations) << 32) | (length & 0xffffffffL));
            String salt64 = Base64.getEncoder().encodeToString(salt.getBytes());
            String hash64 = Base64.getEncoder().encodeToString(key.getEncoded());
            String hash = "$" + algorithm.getCode() + "$" + params + "$" + salt64 + "$" + hash64;
            return new Hash(this, hash, salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + salt + ", #iterations=`" + iterations + "` and length=`" + length + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(String password, String hashed)
    {
        String salt = getSaltFromHash(hashed);

        Hash internalHas = hash(password, salt);

        return slowEquals(internalHas.getResult().getBytes(), hashed.getBytes());
    }

    private String getSaltFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            return new String(Base64.getDecoder().decode(parts[3].getBytes()));
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param a the first byte array
     * @param b the second byte array
     * @return true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }


    public enum Algorithm
    {
        PBKDF2WithHmacSHA1(160, 1), //
        PBKDF2WithHmacSHA224(224, 2), //
        PBKDF2WithHmacSHA256(256, 3), //
        PBKDF2WithHmacSHA384(384, 4), //
        PBKDF2WithHmacSHA512(512, 5);

        private int bits;

        private int code;

        Algorithm(int bits, int code)
        {
            this.bits = bits;
            this.code = code;
        }

        public int getBits()
        {
            return bits;
        }

        public int getCode()
        {
            return code;
        }

        public static Algorithm fromCode(int code)
        {
            for (Algorithm alg : values())
            {
                if (alg.getCode() == code)
                {
                    return alg;
                }
            }
            return null;
        }
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        PBKDF2Function otherStrategy = (PBKDF2Function) obj;
        return this.algorithm.equals(otherStrategy.algorithm) //
                && this.iterations == otherStrategy.iterations //
                && this.length == otherStrategy.length;
    }

    @Override
    public String toString()
    {
        return getClass().getName() + Arrays.toString(new int[] { algorithm.getCode(), iterations, length });
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }
}
