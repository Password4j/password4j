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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;


/**
 * Class containing the implementation of Messaged digest functions provided by {@link MessageDigest}.
 *
 * @author David Bertoldi
 * @see <a href="https://en.wikipedia.org/wiki/Category:Cryptographic_hash_functions">Message digests</a>
 * @since 1.4.0
 */
public class MessageDigestFunction extends AbstractHashingFunction
{
    protected static final SaltOption DEFAULT_SALT_OPTION = SaltOption.APPEND;
    private static final Map<String, MessageDigestFunction> INSTANCES = new ConcurrentHashMap<>();
    private final String algorithm;

    private final SaltOption saltOption;


    MessageDigestFunction(String algorithm, SaltOption saltOption)
    {
        this.algorithm = algorithm;
        this.saltOption = saltOption;
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm message digest algorithm
     * @return a singleton instance
     * @since 1.4.0
     */
    public static MessageDigestFunction getInstance(String algorithm)
    {
        return getInstance(algorithm, DEFAULT_SALT_OPTION);
    }

    /**
     * Creates a singleton instance, depending on the provided
     * algorithm, number of iterations and key length.
     *
     * @param algorithm  hmac algorithm
     * @param saltOption a configuration that specifies how the salt is concatenated to the plain text password
     * @return a singleton instance
     * @since 1.4.0
     */
    public static MessageDigestFunction getInstance(String algorithm, SaltOption saltOption)
    {
        String key = getUID(algorithm, saltOption);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            MessageDigestFunction function = new MessageDigestFunction(algorithm, saltOption);
            INSTANCES.put(key, function);
            return function;
        }
    }

    protected static String getUID(String algorithm, SaltOption saltOption)
    {
        return algorithm + "|" + saltOption.name();
    }

    protected static String toString(String algorithm, SaltOption saltOption)
    {
        return "a=" + algorithm + ", o=" + saltOption.name();
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return hash(plainTextPassword, null);
    }

    @Override
    public Hash hash(byte[] plainTextPasswordAsBytes)
    {
        return hash(plainTextPasswordAsBytes, null);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt));
    }

    @Override
    public Hash hash(byte[] plainTextPasswordAsBytes, byte[] saltAsBytes)
    {
        return internalHash(plainTextPasswordAsBytes, saltAsBytes);
    }

    protected Hash internalHash(byte[] plainTextPassword, byte[] salt)
    {
        byte[] finalCharSequence = concatenateSalt(plainTextPassword, salt);

        byte[] result = getMessageDigest().digest(finalCharSequence);
        return new Hash(this, Utils.toHex(result), result, salt);
    }

    protected MessageDigest getMessageDigest()
    {
        try
        {
            return MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            throw new UnsupportedOperationException("`" + algorithm + "` is not supported by your system.", nsae);
        }
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check(plainTextPassword, hashed, null);
    }

    @Override
    public boolean check(byte[] plainTextPasswordAsBytes, byte[] hashed)
    {
        return check(plainTextPasswordAsBytes, hashed, null);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        Hash hash = internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt));
        return slowEquals(hash.getResult(), hashed);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt)
    {
        Hash hash = internalHash(plainTextPassword, salt);
        return slowEquals(hash.getResultAsBytes(), hashed);
    }

    /**
     * The salt option describes if the Salt is appended or prepended to
     * the plain text password.
     *
     * @return how the salt is concatenated
     * @since 1.5.1
     */
    public SaltOption getSaltOption()
    {
        return saltOption;
    }

    /**
     * The algorithm in use by this instance.
     *
     * @return the algorithm in use
     * @since 1.5.1
     */
    public String getAlgorithm()
    {
        return algorithm;
    }


    private byte[] concatenateSalt(byte[] plainTextPassword, byte[] salt)
    {
        if (salt == null || salt.length == 0)
        {
            return plainTextPassword;
        }

        if (saltOption == SaltOption.PREPEND)
        {
            return Utils.append(salt, plainTextPassword);
        }
        return Utils.append(plainTextPassword, salt);
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '(' + toString(this.algorithm, this.saltOption) + ')';
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
            return true;
        if (!(o instanceof MessageDigestFunction))
            return false;
        MessageDigestFunction other = (MessageDigestFunction) o;
        return algorithm.equals(other.algorithm) //
                && saltOption == other.saltOption;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(algorithm, saltOption);
    }
}
