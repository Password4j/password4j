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
    private static final Map<String, MessageDigestFunction> INSTANCES = new ConcurrentHashMap<>();

    private static final SaltOption DEFAULT_SALT_OPTION = SaltOption.APPEND;

    private final String algorithm;

    private final SaltOption saltOption;


    private MessageDigestFunction(String algorithm, SaltOption saltOption)
    {
        this.algorithm = algorithm;
        this.saltOption = saltOption;
    }

    public static MessageDigestFunction getInstance(String algorithm)
    {
        return getInstance(algorithm, DEFAULT_SALT_OPTION);
    }


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


    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return internalHash(plainTextPassword, null);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return internalHash(plainTextPassword, salt);
    }

    protected Hash internalHash(CharSequence plainTextPassword, String salt)
    {
        try
        {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            CharSequence finalCharSequence = concatenateSalt(plainTextPassword, salt);

            byte[] result = messageDigest.digest(CharSequenceUtils.fromCharSequenceToBytes(finalCharSequence));
            return new Hash(this, CharSequenceUtils.toHex(result), salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            throw new UnsupportedOperationException("`" +  algorithm + "` is not supported by your system.", nsae);
        }
    }


    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        Hash hash = internalHash(plainTextPassword, null);
        return slowEquals(hash.getResult().getBytes(), hashed.getBytes());
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        Hash hash = internalHash(plainTextPassword, salt);
        return slowEquals(hash.getResult().getBytes(), hashed.getBytes());
    }

    private CharSequence concatenateSalt(CharSequence plainTextPassword, CharSequence salt)
    {
        if (saltOption == SaltOption.PREPEND)
        {
            return CharSequenceUtils.append(salt, plainTextPassword);
        }
        return CharSequenceUtils.append(plainTextPassword, salt);
    }

    private static String getUID(String algorithm, SaltOption saltOption)
    {
        return algorithm + "|" + saltOption.name();
    }
}
