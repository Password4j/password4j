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

/**
 * Class in the hierarchy to avoid code duplication.
 *
 * @author David Bertoldi
 * @since 0.1.0
 */
public abstract class AbstractHashingFunction implements HashingFunction
{

    /**
     * Compares two {@link CharSequence}s as byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param a the first CharSequence
     * @param b the second CharSequence
     * @return true if both {@link CharSequence}s are the same, false if not
     */
    protected static boolean slowEquals(CharSequence a, CharSequence b)
    {
        return slowEquals(Utils.fromCharSequenceToBytes(a), Utils.fromCharSequenceToBytes(b));
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
        {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt, CharSequence pepper)
    {
        CharSequence peppered = Utils.append(pepper, plainTextPassword);
        Hash result;
        if (salt == null)
        {
            result = hash(peppered);
        }
        else
        {
            result = hash(peppered, salt);
        }

        result.setPepper(pepper);
        return result;
    }

    @Override
    public Hash hash(byte[] plainTextPassword, byte[] salt, CharSequence pepper)
    {
        byte[] pepperAsBytes = Utils.fromCharSequenceToBytes(pepper);
        byte[] peppered = Utils.append(pepperAsBytes, plainTextPassword);
        Hash result;
        if (salt == null)
        {
            result = hash(peppered);
        }
        else
        {
            result = hash(peppered, salt);
        }

        result.setPepper(pepper);
        return result;
    }

    /**
     * Just calls {@link #check(CharSequence, String)} without salt
     * parameter.
     * <p>
     * Do not override this if the algorithm doesn't need a manually
     * provided salt.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @param salt              the salt used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @since 0.1.0
     */
    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        return check(plainTextPassword, hashed);
    }

    /**
     * Just calls {@link #check(CharSequence, String)} without salt
     * parameter.
     * <p>
     * Do not override this if the algorithm doesn't need a manually
     * provided salt.
     *
     * @param plainTextPassword the plaintext password as bytes array
     * @param hashed            the hash as bytes array
     * @param salt              the salt as bytes array used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @since 1.7.0
     */
    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt)
    {
        return check(plainTextPassword, hashed);
    }

    /**
     * Just calls {@link #check(CharSequence, String, String)}, with a prepended pepper.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @param salt              the salt used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @since 1.5.0
     */
    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt, CharSequence pepper)
    {
        return check(Utils.append(pepper, plainTextPassword), hashed, salt);
    }

    /**
     * Just calls {@link #check(CharSequence, String, String)}, with a prepended pepper.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @param salt              the salt used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @since 1.7.0
     */
    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt, CharSequence pepper)
    {
        byte[] pepperAsBytes = Utils.fromCharSequenceToBytes(pepper);
        return check(Utils.append(pepperAsBytes, plainTextPassword), hashed, salt);
    }

}
