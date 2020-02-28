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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;


public class PBKDF2Function extends AbstractHashingFunction
{
    public static final Algorithm DEFAULT_ALGORITHM = Algorithm.PBKDF2WithHmacSHA512;

    public static final int DEFAULT_ITERATIONS = 64_000;

    public static final int DEFAULT_LENGTH = DEFAULT_ALGORITHM.bits;

    private Algorithm algorithm = DEFAULT_ALGORITHM;

    private int iterations = DEFAULT_ITERATIONS;

    private int length = DEFAULT_LENGTH;



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
            return new Hash(this, getHash(key, salt), salt);
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

    protected String getHash(SecretKey key, String salt)
    {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }


    @Override
    public boolean check(String plain, String hashed, String salt)
    {
        Hash internalHas = hash(plain, salt);
        return slowEquals(internalHas.getResult().getBytes(), hashed.getBytes());
    }

    @Override
    public boolean check(String password, String hashed)
    {
        throw new UnsupportedOperationException("This implementation requires an explicit salt. Use check(String, String, String) method instead.");

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
    protected static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public Algorithm getAlgorithm()
    {
        return algorithm;
    }

    public int getIterations()
    {
        return iterations;
    }

    public int getLength()
    {
        return length;
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
        return getClass().getName() + Arrays.toString(new int[]{algorithm.getCode(), iterations, length});
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }
}
