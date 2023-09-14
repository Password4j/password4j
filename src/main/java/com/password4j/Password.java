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
 * This class provides the two main operations on password: hash and verify.
 * <p>
 * All the methods are static because there's no sense to
 * have an instance of {@link Password}.
 * It represents a facade layer that ease the usage of the
 * package itself and so this should be the only class
 * to be invoked from this package.
 *
 * @author David Bertoldi
 * @since 0.1.1
 */
public class Password
{

    static
    {
        Utils.printBanner(System.out); //NOSONAR
    }

    private Password()
    {
        //
    }

    /**
     * Starts to hash the given plain text password.
     * <p>
     * This method is used to start the setup of a {@link HashBuilder}
     * instance that finally should execute the {@link HashBuilder#with(HashingFunction)}
     * method to hash the password.
     *
     * @param plainTextPassword the plain text password
     * @return a builder instance of {@link HashBuilder}
     * @throws BadParametersException if any of the arguments are null.
     * @since 0.1.1
     */
    public static HashBuilder hash(CharSequence plainTextPassword)
    {
        if (plainTextPassword == null)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return new HashBuilder(plainTextPassword);
    }

    /**
     * Starts to hash the given plain text password.
     * <p>
     * This method is used to start the setup of a {@link HashBuilder}
     * instance that finally should execute the {@link HashBuilder#with(HashingFunction)}
     * method to hash the password.
     *
     * @param plainTextPassword the plain text password as bytes array
     * @return a builder instance of {@link HashBuilder}
     * @throws BadParametersException if any of the arguments are null.
     * @since 1.7.0
     */
    public static HashBuilder hash(byte[] plainTextPassword)
    {
        if (plainTextPassword == null || plainTextPassword.length == 0)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return new HashBuilder(plainTextPassword);
    }


    /**
     * Starts to verify if a hash string has been generated with
     * the given plain text password.
     * <p>
     * This method is used to start the setup of an {@link HashChecker}
     * instance that finally should execute the {@link HashChecker#with(HashingFunction)}
     * method to verify the hash.
     *
     * @param plainTextPassword the plain text password
     * @param hash              a hash string
     * @return a builder instance of {@link HashChecker}
     * @throws BadParametersException if any of the arguments are null.
     * @since 0.1.1
     */
    public static HashChecker check(CharSequence plainTextPassword, String hash)
    {
        if (hash == null || plainTextPassword == null)
        {
            throw new BadParametersException("Hash or plain cannot be null");
        }
        return new HashChecker(plainTextPassword, hash);
    }


    /**
     * Starts to verify if a hash string has been generated with
     * the given plain text password.
     * <p>
     * This method is used to start the setup of an {@link HashChecker}
     * instance that finally should execute the {@link HashChecker#with(HashingFunction)}
     * method to verify the hash.
     *
     * @param plainTextPassword the plain text password as bytes  array
     * @param hash              a hash string as bytes array
     * @return a builder instance of {@link HashChecker}
     * @throws BadParametersException if any of the arguments are null.
     * @since 1.7.0
     */
    public static HashChecker check(byte[] plainTextPassword, byte[] hash)
    {
        if (hash == null || plainTextPassword == null || hash.length == 0 || plainTextPassword.length == 0)
        {
            throw new BadParametersException("Hash or plain cannot be null");
        }
        return new HashChecker(plainTextPassword, hash);
    }

    /**
     * Starts to verify if a hash object has been generated with
     * the given plain text password.
     * <p>
     * This method uses the {@link HashingFunction} used to calculate the given {@link Hash}.
     * Il the password is null, this returns false;
     * otherwise {@link HashingFunction#check(CharSequence, String)} is invoked.
     *
     * @param plainTextPassword the original password.
     * @param hashObject        an {@link Hash} object.
     * @return true if the check passes, false otherwise.
     * @throws BadParametersException if the Hash is null or if there's no hashing function defined in it.
     * @since 1.0.3
     */
    public static boolean check(CharSequence plainTextPassword, Hash hashObject)
    {
        return check(Utils.fromCharSequenceToBytes(plainTextPassword), hashObject);
    }

    /**
     * Starts to verify if a hash object has been generated with
     * the given plain text password.
     * <p>
     * This method uses the {@link HashingFunction} used to calculate the given {@link Hash}.
     * Il the password is null, this returns false;
     * otherwise {@link HashingFunction#check(CharSequence, String)} is invoked.
     *
     * @param plainTextPassword the original password as bytes array.
     * @param hashObject        an {@link Hash} object.
     * @return true if the check passes, false otherwise.
     * @throws BadParametersException if the Hash is null or if there's no hashing function defined in it.
     * @since 1.7.0
     */
    public static boolean check(byte[] plainTextPassword, Hash hashObject)
    {
        if (hashObject == null || hashObject.getHashingFunction() == null)
        {
            throw new BadParametersException("Invalid Hash object. " + (hashObject != null ? hashObject.toString() : null));
        }
        if (plainTextPassword == null)
        {
            return false;
        }

        return hashObject.getHashingFunction().check(plainTextPassword, hashObject.getResultAsBytes(), hashObject.getSaltBytes(), hashObject.getPepper());
    }

}
