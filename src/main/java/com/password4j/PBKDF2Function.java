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
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Class containing the implementation of PBKDF2 function and its parameters.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>
 * @since 0.1.0
 */
public class PBKDF2Function extends AbstractHashingFunction
{
    private Hmac algorithm;

    private int iterations;

    private int length;

    private static Map<String, PBKDF2Function> instances = new ConcurrentHashMap<>();

    private static final String ALGORITHM_PREFIX = "PBKDF2WithHmac";

    protected PBKDF2Function()
    {
        //
    }

    protected PBKDF2Function(int iterations, int length)
    {
        this.iterations = iterations;
        this.length = length;
    }

    protected PBKDF2Function(Hmac algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithm = algorithm;
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm  hmac algorithm
     * @param iterations number of iterations
     * @param length     length of the derived key
     * @return a singleton instance
     * @since 0.1.0
     */
    public static PBKDF2Function getInstance(Hmac algorithm, int iterations, int length)
    {
        String key = getUID(algorithm, iterations, length);
        if (instances.containsKey(key))
        {
            return instances.get(key);
        }
        else
        {
            PBKDF2Function function = new PBKDF2Function(algorithm, iterations, length);
            instances.put(key, function);
            return function;
        }
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm  string veriong of hmac algorithm
     * @param iterations number of iterations
     * @param length     length of the derived key
     * @return a singleton instance
     * @since 0.1.0
     */
    public static PBKDF2Function getInstance(String algorithm, int iterations, int length)
    {
        try
        {
            return getInstance(Hmac.valueOf(algorithm), iterations, length);
        }
        catch (IllegalArgumentException iae)
        {
            throw new UnsupportedOperationException("Algorithm `" + algorithm + "` is not recognized.", iae);
        }
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plainTextPassword, new String(salt));
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        try
        {
            SecretKey key = internalHash(plainTextPassword, salt, this.algorithm, this.iterations, this.length);
            return new Hash(this, getHash(key, salt), salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + salt + ", #iterations=" + iterations + " and length=" + length;
            throw new BadParametersException(message, e);
        }
    }

    protected static SecretKey internalHash(CharSequence plainTextPassword, String salt, Hmac algorithm, int iterations, int length)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        if(salt == null)
        {
            throw new IllegalArgumentException("Salt cannot be null");
        }
        return internalHash(Utilities.fromCharSequenceToChars(plainTextPassword), salt.getBytes(), algorithm, iterations, length);
    }

    protected static SecretKey internalHash(char[] plain, byte[] salt, Hmac algorithm, int iterations, int length)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_PREFIX + algorithm.name());
        PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, length);
        return secretKeyFactory.generateSecret(spec);
    }

    protected String getHash(SecretKey key, String salt)
    {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        Hash internalHash = hash(plainTextPassword, salt);
        return slowEquals(internalHash.getResult().getBytes(), hashed.getBytes());
    }

    @Override
    public boolean check(CharSequence plainTexPassword, String hashed)
    {
        throw new UnsupportedOperationException(
                "This implementation requires an explicit salt. Use check(CharSequence, String, String) method instead.");

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


    public Hmac getAlgorithm()
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


    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !getClass().equals(obj.getClass()))
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
        return getClass().getSimpleName() + '[' + getUID(this.algorithm, this.iterations, this.length) + ']';
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }

    protected static String getUID(Hmac algorithm, int iterations, int length)
    {
        return algorithm.code() + "|" + iterations + "|" + length;
    }

}
