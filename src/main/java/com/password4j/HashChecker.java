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

/**
 * Builder class that helps to create a chain of parameters to be used
 * in the verification process.
 *
 * @param <C> extends HashChecker.
 * @author David Bertoldi
 * @since 1.0.0
 */
public class HashChecker<C extends HashChecker<?>>
{
    private String hash;

    private String salt;

    private String pepper;

    private CharSequence plainTextPassword;

    @SuppressWarnings("unused")
    private HashChecker()
    {
        //
    }

    /**
     * @param plainTextPassword the plain text password
     * @param hash              the hash to verify
     * @since 1.0.0
     */
    public HashChecker(CharSequence plainTextPassword, String hash)
    {
        this.hash = hash;
        this.plainTextPassword = plainTextPassword;
    }

    /**
     * Concatenates the provided string with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the algorithm.
     *
     * @param pepper cryptographic pepper
     * @return this builder
     * @since 1.0.0
     */
    public C addPepper(String pepper)
    {
        this.pepper = pepper;
        return (C) this;
    }

    /**
     * Concatenates the pepper configured in your `psw4j.properties` file with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the algorithm.
     *
     * @return this builder
     * @see PepperGenerator#get()
     */
    public C addPepper()
    {
        this.pepper = PepperGenerator.get();
        return (C) this;
    }

    /**
     * Add a cryptographic salt in the verifying process.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param salt cryptographic salt
     * @return this builder
     * @since 1.0.0
     */
    public C addSalt(String salt)
    {
        this.salt = salt;
        return (C) this;
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with a specific implementation of {@link HashingFunction}.
     * <p>
     * This method does not read the configurations in the `psw4j.properties` file.
     *
     * @param hashingFunction a CHF
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @since 1.0.0
     */
    public boolean with(HashingFunction hashingFunction)
    {
        if (plainTextPassword == null)
        {
            return false;
        }

        CharSequence peppered = plainTextPassword;
        if (StringUtils.isNotEmpty(this.pepper))
        {
            peppered = Utilities.append(this.pepper, peppered);
        }

        return hashingFunction.check(peppered, hash, salt);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link PBKDF2Function}.
     * <p>
     * This method read the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getPBKDF2Instance()
     * @since 1.0.0
     */
    public boolean withPBKDF2()
    {
        PBKDF2Function pbkdf2 = AlgorithmFinder.getPBKDF2Instance();
        return with(pbkdf2);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link CompressedPBKDF2Function}.
     * <p>
     * This method read the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getCompressedPBKDF2Instance()
     * @since 1.0.0
     */
    public boolean withCompressedPBKDF2()
    {
        PBKDF2Function pbkdf2 = AlgorithmFinder.getCompressedPBKDF2Instance();
        return with(pbkdf2);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link SCryptFunction}.
     * <p>
     * This method read the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getSCryptInstance()
     * @since 1.0.0
     */
    public boolean withSCrypt()
    {
        SCryptFunction scrypt = AlgorithmFinder.getSCryptInstance();
        return with(scrypt);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link BCryptFunction}.
     * <p>
     * This method read the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getBCryptInstance()
     * @since 1.0.0
     */
    public boolean withBCrypt()
    {
        return with(AlgorithmFinder.getBCryptInstance());
    }


}
