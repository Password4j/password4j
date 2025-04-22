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

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Class containing the implementation of PBKDF2 function and its parameters.
 * <p>
 * The main difference between {@link PBKDF2Function} is the hash produced: the configurations of the CHF,
 * the salt and the hash are encoded inside it.
 * <p>
 * The produced hash is in the form
 * <p>
 * <code>
 * $algorithm$parameters$salt$hash
 * </code>
 * <p>
 * Assuming {@code $} as delimiter.
 * <p>
 * <ul>
 *     <li>
 *         The algorithm is encoded with its numeric uid {@link Hmac#code()}
 *     </li>
 *     <li>
 *         Parameters are encoded in one integer where the length occupies the first 32bit and
 *          the number of iterations the remaining 32 bits.
 *     </li>
 *     <li>
 *         Salt is encoded in Base64
 *     </li>
 *     <li>
 *         Hash is encoded in Base64 as in {@link PBKDF2Function}
 *     </li>
 * </ul>
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>
 * @since 0.1.0
 */
public class CompressedPBKDF2Function extends PBKDF2Function
{

    private static final Map<String, CompressedPBKDF2Function> INSTANCES = new ConcurrentHashMap<>();

    private static final char DELIMITER = PropertyReader.readChar("hash.pbkdf2.delimiter", '$');

    protected CompressedPBKDF2Function()
    {
        super();
    }

    protected CompressedPBKDF2Function(Hmac fromCode, int iterations, int length)
    {
        super(fromCode, iterations, length);
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
    public static CompressedPBKDF2Function getInstance(Hmac algorithm, int iterations, int length)
    {
        String key = getUID(algorithm.name(), iterations, length);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            CompressedPBKDF2Function function = new CompressedPBKDF2Function(algorithm, iterations, length);
            INSTANCES.put(key, function);
            return function;
        }
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm  string version of hmac algorithm. This must me mapped in {@link Hmac}.
     * @param iterations number of iterations
     * @param length     length of the derived key
     * @return a singleton instance
     * @throws IllegalArgumentException if {@code algorithm} is not mapped in {@link Hmac}.
     * @since 0.1.0
     */
    public static CompressedPBKDF2Function getInstance(String algorithm, int iterations, int length)
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

    /**
     * Reads the configuration contained in the given hash and
     * builds a singleton instance based on these configurations.
     *
     * @param hashed an already hashed password
     * @return a singleton instance based on the given hash
     * @since 1.0.0
     */
    public static CompressedPBKDF2Function getInstanceFromHash(String hashed)
    {
        String[] parts = getParts(hashed);
        if (parts.length == 5)
        {
            int algorithm = Integer.parseInt(parts[1]);
            long configuration = Long.parseLong(parts[2]);

            int iterations = (int) (configuration >> 32);
            int length = (int) configuration;

            return CompressedPBKDF2Function.getInstance(Hmac.fromCode(algorithm), iterations, length);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    protected static List<byte[]> getParts(byte[] hashed)
    {
        return Utils.split(hashed, (byte) DELIMITER);
    }

    protected static String[] getParts(String hashed)
    {
        String regex = "\\" + DELIMITER;
        return hashed.split(regex);
    }

    @Override
    protected String getHash(byte[] encodedKey, byte[] salt)
    {
        String params = Long.toString((((long) getIterations()) << 32) | (getLength() & 0xffffffffL));
        String salt64 = Utils.encodeBase64(salt);
        String hash64 = super.getHash(encodedKey, salt);
        return "$" + algorithm.code() + "$" + params + "$" + salt64 + "$" + hash64;
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(hashed));
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed)
    {
        byte[] salt = getSaltFromHash(hashed);
        Hash internalHas = hash(plainTextPassword, salt);

        return slowEquals(internalHas.getResultAsBytes(), hashed);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        byte[] hashAsBytes = Utils.fromCharSequenceToBytes(hashed);
        byte[] realSalt = getSaltFromHash(hashAsBytes);
        byte[] plainTextPasswordAsBytes = Utils.fromCharSequenceToBytes(plainTextPassword);
        Hash internalHash = hash(plainTextPasswordAsBytes, realSalt);
        return slowEquals(internalHash.getResult(), hashed);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt)
    {
        byte[] realSalt = getSaltFromHash(hashed);
        Hash internalHash = hash(plainTextPassword, realSalt);
        return slowEquals(internalHash.getResultAsBytes(), hashed);
    }

    private byte[] getSaltFromHash(byte[] hashed)
    {
        List<byte[]> parts = getParts(hashed);
        if (parts.size() == 5)
        {
            return Utils.decodeBase64(parts.get(3));
        }
        throw new BadParametersException("`" + Utils.fromBytesToString(hashed) + "` is not a valid hash");
    }
}
