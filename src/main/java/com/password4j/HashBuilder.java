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
 * Builder class that helps to create a chain of parameters to be used
 * in the hashing process.
 *
 * @author David Bertoldi
 * @since 1.0.0
 */
public class HashBuilder
{
    protected byte[] salt;
    protected CharSequence pepper;
    private byte[] plainTextPassword;

    @SuppressWarnings("unused")
    private HashBuilder()
    {
        //
    }

    /**
     * @param plainTextPassword the plain text password
     * @since 1.0.0
     */
    protected HashBuilder(CharSequence plainTextPassword)
    {
        this.plainTextPassword = Utils.fromCharSequenceToBytes(plainTextPassword);
    }

    /**
     * @param plainTextPasswordAsBytes the plain text password as bytes array
     * @since 1.7.0
     */
    protected HashBuilder(byte[] plainTextPasswordAsBytes)
    {
        this.plainTextPassword = plainTextPasswordAsBytes;
    }

    /**
     * Add a cryptographic salt in the hashing process.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param salt cryptographic salt
     * @return this builder
     * @since 1.0.0
     */
    public HashBuilder addSalt(String salt)
    {
        this.salt = Utils.fromCharSequenceToBytes(salt);
        return this;
    }

    /**
     * Add a cryptographic salt in the hashing process.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param saltAsBytes cryptographic salt as bytes array
     * @return this builder
     * @since 1.7.0
     */
    public HashBuilder addSalt(byte[] saltAsBytes)
    {
        this.salt = saltAsBytes;
        return this;
    }

    /**
     * Add a random cryptographic salt in the hashing process.
     * The salt is applied differently depending on the chosen algorithm.
     * <p>
     * Calling this method can be omitted for all the CHFs that require a salt.
     *
     * @return this builder
     * @see SaltGenerator#generate() for more information about the length of the product
     * @since 1.0.0
     */
    public HashBuilder addRandomSalt()
    {
        this.salt = SaltGenerator.generate();
        return this;
    }

    /**
     * Add a random cryptographic salt in the hashing process with a given length.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param length the length of the salt produced
     * @return this builder
     * @throws BadParametersException if the length is non-positive
     * @see SaltGenerator#generate() for more information about the length of the product
     * @since 1.0.0
     */
    public HashBuilder addRandomSalt(int length)
    {
        if (length <= 0)
        {
            throw new BadParametersException("Salt cannot have a non-positive length");
        }
        else
        {
            this.salt = SaltGenerator.generate(length);
        }
        return this;
    }

    /**
     * Concatenates the pepper configured in your `psw4j.properties` file with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the algorithm.
     *
     * @return this builder
     * @see PepperGenerator#get()
     */
    public HashBuilder addPepper()
    {
        this.pepper = PepperGenerator.get();
        return this;
    }

    /**
     * Concatenates the provided string with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the algorithm.
     *
     * @param pepper cryptographic pepper
     * @return this builder
     * @since 1.0.0
     */
    public HashBuilder addPepper(CharSequence pepper)
    {
        this.pepper = pepper;
        return this;
    }

    /**
     * Hashes the previously given plain text password
     * with a specific implementation of {@link HashingFunction}.
     * <p>
     * This method does not read the configurations in the `psw4j.properties` file.
     *
     * @param hashingFunction a CHF
     * @return a {@link Hash} object
     * @since 1.0.0
     */
    public Hash with(HashingFunction hashingFunction)
    {
        return hashingFunction.hash(plainTextPassword, salt, pepper);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link PBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return a {@link Hash} object
     * @see AlgorithmFinder#getPBKDF2Instance()
     * @see #with(HashingFunction)
     * @since 1.0.0
     */
    public Hash withPBKDF2()
    {
        return with(AlgorithmFinder.getPBKDF2Instance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link CompressedPBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return an {@link Hash} object
     * @see AlgorithmFinder#getCompressedPBKDF2Instance()
     * @see #with(HashingFunction)
     * @since 1.0.0
     */
    public Hash withCompressedPBKDF2()
    {
        return with(AlgorithmFinder.getCompressedPBKDF2Instance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BcryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return an {@link Hash} object
     * @see AlgorithmFinder#getBcryptInstance()
     * @see #with(HashingFunction)
     * @since 1.0.0
     */
    public Hash withBcrypt()
    {
        return with(AlgorithmFinder.getBcryptInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link ScryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return an {@link Hash} object
     * @see AlgorithmFinder#getScryptInstance()
     * @see #with(HashingFunction)
     * @since 1.0.0
     */
    public Hash withScrypt()
    {
        return with(AlgorithmFinder.getScryptInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link MessageDigestFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return a {@link Hash} object
     * @see AlgorithmFinder#getPBKDF2Instance()
     * @see #with(HashingFunction)
     * @since 1.4.0
     */
    public Hash withMessageDigest()
    {
        return with(AlgorithmFinder.getMessageDigestInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link Argon2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return a {@link Hash} object
     * @see AlgorithmFinder#getArgon2Instance()
     * @see #with(HashingFunction)
     * @since 1.5.0
     */
    public Hash withArgon2()
    {
        return with(AlgorithmFinder.getArgon2Instance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BalloonHashingFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction)}
     *
     * @return a {@link Hash} object
     * @see AlgorithmFinder#getArgon2Instance()
     * @see #with(HashingFunction)
     * @since 1.8.0
     */
    public Hash withBalloonHashing()
    {
        return with(AlgorithmFinder.getBalloonHashingInstance());
    }

}
