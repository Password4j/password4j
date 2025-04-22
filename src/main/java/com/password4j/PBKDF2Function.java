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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
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
    private static final Map<String, PBKDF2Function> INSTANCES = new ConcurrentHashMap<>();

    private static final String ALGORITHM_PREFIX = "PBKDF2WithHmac";

    protected Hmac algorithm;

    protected String algorithmAsString;

    protected int iterations;

    protected int length;

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
        this.algorithmAsString = algorithm.name();
    }

    protected PBKDF2Function(String algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithmAsString = algorithm;
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
        return getInstance(algorithm.name(), iterations, length);
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm  string version of hmac algorithm
     * @param iterations number of iterations
     * @param length     length of the derived key
     * @return a singleton instance
     * @since 0.1.0
     */
    public static PBKDF2Function getInstance(String algorithm, int iterations, int length)
    {
        String key = getUID(algorithm, iterations, length);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            PBKDF2Function function = new PBKDF2Function(algorithm, iterations, length);
            INSTANCES.put(key, function);
            return function;
        }
    }

    protected static SecretKey internalHash(byte[] plainTextPassword, byte[] salt, String algorithm, int iterations, int length) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        if (salt == null)
        {
            throw new IllegalArgumentException("Salt cannot be null");
        }
        return internalHash(Utils.fromBytesToChars(plainTextPassword), salt, algorithm, iterations, length);
    }

    protected static SecretKey internalHash(char[] plain, byte[] salt, String algorithm, int iterations, int length)
            throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM_PREFIX + algorithm);
        PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, length);
        return secretKeyFactory.generateSecret(spec);
    }

    protected static String getUID(String algorithm, int iterations, int length)
    {
        return algorithm + "|" + iterations + "|" + length;
    }

    protected static String toString(String algorithm, int iterations, int length)
    {
        return "a=" + algorithm + ", i=" + iterations + ", l=" + length;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(Utils.fromCharSequenceToBytes(plainTextPassword), salt);
    }

    @Override
    public Hash hash(byte[] plainTextPasswordAsBytes)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plainTextPasswordAsBytes, salt);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return hash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt));
    }

    @Override
    public Hash hash(byte[] plainTextPassword, byte[] salt)
    {
        try
        {
            SecretKey key = internalHash(plainTextPassword, salt, this.algorithmAsString, this.iterations, this.length);
            byte[] encodedKey = key.getEncoded();
            return new Hash(this, getHash(encodedKey, salt), encodedKey, salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + Arrays.toString(salt) + ", iterations=" + iterations + " and length=" + length;
            throw new BadParametersException(message, e);
        }
    }

    /**
     * Overridable PBKDF2 generator
     *
     * @param encodedKey secret encodedKey
     * @param salt       cryptographic salt
     * @return the PBKDF2 hash string
     */
    protected String getHash(byte[] encodedKey, byte[] salt)
    {
        return Utils.encodeBase64(encodedKey);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check((byte[]) null, null);
    }

    @Override
    public boolean check(byte[] plainTextPasswordAsBytes, byte[] hashed)
    {
        throw new UnsupportedOperationException("This implementation requires an explicit salt.");

    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        Hash internalHash = hash(plainTextPassword, salt);
        return slowEquals(internalHash.getResult(), hashed);
    }

    @Override
    public boolean check(byte[] plainTextPasswordAsBytes, byte[] hashed, byte[] salt)
    {
        Hash internalHash = hash(plainTextPasswordAsBytes, salt);
        return slowEquals(internalHash.getResultAsBytes(), hashed);
    }


    public String getAlgorithm()
    {
        return algorithmAsString;
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
        return this.algorithmAsString.equals(otherStrategy.algorithmAsString) //
                && this.iterations == otherStrategy.iterations //
                && this.length == otherStrategy.length;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '(' + toString(this.algorithmAsString, this.iterations, this.length) + ')';
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(algorithmAsString, iterations, length);
    }

}
