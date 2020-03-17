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

import org.apache.commons.lang3.StringUtils;

import java.util.function.BiFunction;
import java.util.function.Function;

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
        return hash(plainTextPassword, HashBuilder::new);
    }

    /**
     * Starts to verify if an hash string has been generated with
     * the given plain text password.
     * <p>
     * This method is used to start the setup of an {@link HashChecker}
     * instance that finally should execute the {@link HashChecker#with(HashingFunction)}
     * method to verify the hash.
     *
     * @param plainTextPassword the plain text password
     * @param hash              an hash string
     * @return a builder instance of {@link HashChecker}
     * @throws BadParametersException if any of the arguments are null.
     * @since 0.1.1
     */
    public static HashChecker check(CharSequence plainTextPassword, String hash)
    {
        return check(plainTextPassword, hash, HashChecker::new);
    }

    /**
     * Starts to verify if an hash object has been generated with
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
        if (hashObject == null || hashObject.getHashingFunction() == null)
        {
            throw new BadParametersException("Invalid Hash object. " +
                    (hashObject != null ? hashObject.toString() : null));
        }
        if (plainTextPassword == null)
        {
            return false;
        }

        CharSequence peppered = plainTextPassword;
        if (StringUtils.isNotEmpty(hashObject.getPepper()))
        {
            peppered = Utilities.append(hashObject.getPepper(), peppered);
        }

        return hashObject.getHashingFunction().check(peppered, hashObject.getResult(), hashObject.getSalt());
    }

    /**
     * Starts to hash the given plain text password with a custom builder.
     * <p>
     * This method is used to start the setup of a {@link HashBuilder}
     * instance that finally should execute the {@link HashBuilder#with(HashingFunction)}
     * method (or an equivalent method) to hash the password.
     * <p>
     * The extended {@link HashBuilder} is built with a {@link Function}
     * because it is easier to invoke, rather than call
     * the constructor with the same argument.
     * <p>
     * For example:<br/>
     * <code>
     * Passowrd.hash("password", CustomHashBuilder::new);
     * </code>
     *
     * @param plainTextPassword the plain text password
     * @param builderFunction   any lambda function or method reference
     *                          that returns an instance of the extended
     *                          {@link HashBuilder}.
     * @return a builder instance of {@link HashBuilder}
     * @throws BadParametersException if any of the arguments are null.
     * @since 0.1.1
     */
    public static <B extends HashBuilder<?>> B hash(CharSequence plainTextPassword, Function<CharSequence, B> builderFunction)
    {
        if (builderFunction == null)
        {
            throw new BadParametersException("HashBuilder construction method cannot be null");
        }
        if (plainTextPassword == null)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return builderFunction.apply(plainTextPassword);
    }

    /**
     * Verify if an hash string has been generated with
     * the given plain text password with a custom verifier.
     * <p>
     * This method is used to start the setup of a custom {@link HashChecker}
     * instance that finally should execute the {@link HashChecker#with(HashingFunction)}
     * (or an equivalent method) to verify the hash.
     * <p>
     * The extended {@link HashChecker} is built with a {@link BiFunction}
     * because it is easier to invoke, rather than call
     * the constructor with the same two arguments.
     * <p>
     * For example:<br/>
     * <code>
     * Passowrd.check("password", "hash", CustomHashChecker::new);
     * </code>
     *
     * @param plainTextPassword the plain text password
     * @param hash              an hash string
     * @param checkerBiFunction any lambda function or method reference
     *                          that returns an instance of the extended
     *                          {@link HashChecker}.
     * @return a builder instance of {@link HashChecker}
     * @throws BadParametersException if any of the arguments are null.
     * @since 0.2.1
     */
    public static <C extends HashChecker<?>> C check(CharSequence plainTextPassword, String hash, BiFunction<CharSequence, String, C> checkerBiFunction)
    {
        if (checkerBiFunction == null)
        {
            throw new BadParametersException("HashChecker construction method cannot be null");
        }
        if (hash == null || plainTextPassword == null)
        {
            throw new BadParametersException("Hash or plain cannot be null");
        }
        return checkerBiFunction.apply(plainTextPassword, hash);
    }

}
