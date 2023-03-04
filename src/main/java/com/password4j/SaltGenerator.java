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

import java.security.SecureRandom;


/**
 * This class contains static functions that
 * help to create a secure salt.
 * <p>
 * In cryptography, a salt is random data that is used as
 * an additional input to a CHF.
 *
 * @author David Bertoldi
 * @since 0.1.0
 */
public class SaltGenerator
{

    private SaltGenerator()
    {
        //
    }

    /**
     * Generates an array of {@code byte}s that can be used
     * as salt by the CHFs.
     * The generated salt is created by a cryptographically
     * strong random number generator (RNG).
     * <p>
     * The parameter length must be a non-negative number,
     * otherwise a {@link BadParametersException} is thrown.
     *
     * @param length of the returned byte array
     * @return a salt as array of {@code byte}s
     * @throws BadParametersException if the length is negative
     * @since 0.1.0
     */
    public static byte[] generate(int length)
    {
        if (length < 0)
        {
            throw new BadParametersException("Salt length cannot be negative");
        }
        byte[] salt = new byte[length];
        SecureRandom sr = AlgorithmFinder.getSecureRandom();
        sr.nextBytes(salt);
        return salt;
    }

    /**
     * Generates an array of {@code byte}s that can be used
     * as salt by the CHFs.
     * The generated salt is created by a cryptographically
     * strong random number generator (RNG).
     * <p>
     * The length of the array is 64.
     *
     * @return a salt as array of {@code byte}s
     * @since 0.1.0
     */
    public static byte[] generate()
    {
        return generate(get());
    }

    /**
     * Get the length of salt from configurations and
     * must be stored in a location different from the one used
     * for the passwords.
     * <p>
     * It can be set in the <i>psw4j.properties</i> file with
     * the property {@code global.salt.length}.
     * <p>
     * If the <i>psw4j.properties</i> or the property {@code global.salt.length}
     * are not found, {@code null} is returned.
     *
     * @return a shared pepper set in the <i>psw4j.properties</i> file.
     * @since 1.7.0
     */
    public static int get()
    {
        return PropertyReader.readInt("global.salt.length", 64, "Global salt length is not defined in properties file");
    }

}
