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

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.SecretKey;

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
     * @throws IllegalArgumentException if {@code algorithm} is not mapped in {@link Hmac}.
     * @return a singleton instance
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


    protected CompressedPBKDF2Function(Hmac fromCode, int iterations, int length)
    {
        super(fromCode, iterations, length);
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


    @Override
    protected String getHash(SecretKey key, String salt)
    {
        String params = Long.toString((((long) getIterations()) << 32) | (getLength() & 0xffffffffL));
        String salt64 = Base64.getEncoder().encodeToString(salt.getBytes());
        String hash64 = super.getHash(key, salt);
        return "$" + algorithm.code() + "$" + params + "$" + salt64 + "$" + hash64;
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        String salt = getSaltFromHash(hashed);
        Hash internalHas = hash(plainTextPassword, salt);

        return slowEquals(internalHas.getResult().getBytes(), hashed.getBytes());
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        String realSalt = getSaltFromHash(hashed);
        Hash internalHas = hash(plainTextPassword, realSalt);
        return slowEquals(internalHas.getResult().getBytes(), hashed.getBytes());
    }

    private String getSaltFromHash(String hashed)
    {
        String[] parts = getParts(hashed);
        if (parts.length == 5)
        {
            return new String(Base64.getDecoder().decode(parts[3].getBytes()));
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }


    protected static String[] getParts(String hashed)
    {
        return hashed.split(new StringBuilder(2).append('\\').append(DELIMITER).toString());
    }
}
