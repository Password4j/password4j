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
 * This class contains static functions that
 * help to create a secure pepper.
 * <p>
 * In cryptography, a pepper is a secret added to a password
 * prior to being hashed with a CHF.
 *
 * @author David Bertoldi
 * @since 0.1.1
 */
public class PepperGenerator
{

    private PepperGenerator()
    {
        //
    }

    /**
     * Generates a {@link String} that can be used as pepper
     * by a CHF.
     * The generated pepper is created by a cryptographically
     * strong random number generator (RNG).
     * <p>
     * The parameter length must be a non-negative number,
     * otherwise a {@link BadParametersException} is thrown.
     *
     * @param length of the returned string
     * @return a pepper of the given length
     * @throws BadParametersException if the length is negative
     * @since 0.1.1
     */
    public static String generate(int length)
    {
        if (length < 0)
        {
            throw new BadParametersException("Pepper length cannot be negative");
        }
        return Utils.randomPrintable(length);
    }

    /**
     * Generates a {@link String} that can be used as pepper
     * by a CHF.
     * The generated pepper is created by a cryptographically
     * strong random number generator (RNG).
     * <p>
     * The pepper generated is 24 characters long.
     *
     * @return a pepper as {@link String}
     * @since 0.1.1
     */
    public static String generate()
    {
        return generate(24);
    }

    /**
     * Peppers by definition are shared between all passwords and
     * must be stored in a location different from the one used
     * for the passwords.
     * <p>
     * It can be set in the <i>psw4j.properties</i> file with
     * the property {@code global.pepper}.
     * <p>
     * If the <i>psw4j.properties</i> or the property {@code global.pepper}
     * are not found, {@code null} is returned.
     *
     * @return a shared pepper set in the <i>psw4j.properties</i> file.
     * @since 0.1.1
     */
    public static String get()
    {
        return PropertyReader.readString("global.pepper", null, "Global pepper is not defined");
    }

}
