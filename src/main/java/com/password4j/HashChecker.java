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
 * in the verification process.
 *
 * @author David Bertoldi
 * @since 1.0.0
 */
public class HashChecker
{
    protected byte[] hashed;
    protected byte[] salt;
    private byte[] plainTextPassword;
    private CharSequence pepper;


    @SuppressWarnings("unused")
    private HashChecker()
    {
        //
    }

    /**
     * @param plainTextPassword the plain text password
     * @param hashed            the hash to verify
     * @since 1.0.0
     */
    HashChecker(CharSequence plainTextPassword, String hashed)
    {
        this.hashed = Utils.fromCharSequenceToBytes(hashed);
        this.plainTextPassword = Utils.fromCharSequenceToBytes(plainTextPassword);
    }

    /**
     * @param plainTextPassword the plain text password as bytes array
     * @param hashed            the hash to verify as bytes array
     * @since 1.7.0
     */
    HashChecker(byte[] plainTextPassword, byte[] hashed)
    {
        this.hashed = hashed;
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
    public HashChecker addPepper(CharSequence pepper)
    {
        this.pepper = pepper;
        return this;
    }

    /**
     * Concatenates the pepper configured in your `psw4j.properties` file with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the algorithm.
     *
     * @return this builder
     * @see PepperGenerator#get()
     */
    public HashChecker addPepper()
    {
        this.pepper = PepperGenerator.get();
        return this;
    }

    /**
     * Add a cryptographic salt in the verifying process.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param salt cryptographic salt
     * @return this builder
     * @since 1.0.0
     */
    public HashChecker addSalt(String salt)
    {
        this.salt = Utils.fromCharSequenceToBytes(salt);
        return this;
    }

    /**
     * Add a cryptographic salt in the verifying process.
     * The salt is applied differently depending on the chosen algorithm.
     *
     * @param salt cryptographic salt as bytes array
     * @return this builder
     * @since 1.7.0
     */
    public HashChecker addSalt(byte[] salt)
    {
        this.salt = salt;
        return this;
    }

    /**
     * Creates a builder to update the hash.
     * The actual  salt and pepper are taken from the original check request.
     * <p>
     * In order to declare a new salt or pepper use ,}
     *
     * @return the updater
     * @since 1.3.0
     */
    public HashUpdater andUpdate()
    {
        return new HashUpdater(this, new HashBuilder(plainTextPassword).addPepper(pepper).addSalt(salt));
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
        if (plainTextPassword == null || plainTextPassword.length == 0)
        {
            return false;
        }

        return hashingFunction.check(plainTextPassword, hashed, salt, pepper);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link PBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
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
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
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
     * with {@link ScryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getScryptInstance()
     * @since 1.0.0
     */
    public boolean withScrypt()
    {
        ScryptFunction scrypt = AlgorithmFinder.getScryptInstance();
        return with(scrypt);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link BcryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getBcryptInstance()
     * @since 1.0.0
     */
    public boolean withBcrypt()
    {
        return with(AlgorithmFinder.getBcryptInstance());
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link MessageDigestFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getMessageDigestInstance()
     * @since 1.4.0
     */
    public boolean withMessageDigest()
    {
        return with(AlgorithmFinder.getMessageDigestInstance());
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link Argon2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getArgon2Instance()
     * @since 1.5.0
     */
    public boolean withArgon2()
    {
        Argon2Function argon2 = AlgorithmFinder.getArgon2Instance();
        return with(argon2);
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with {@link BalloonHashingFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     *
     * @return true if the hash was produced by the given plain text password; false otherwise.
     * @see AlgorithmFinder#getBalloonHashingInstance()
     * @since 1.5.0
     */
    public boolean withBalloonHashing()
    {
        BalloonHashingFunction balloon = AlgorithmFinder.getBalloonHashingInstance();
        return with(balloon);
    }

    /**
     * This method returns the String version of the hash bytes. This
     * should be always a safe operation when using ISO-8859-1 encoding.
     *
     * @return String version of the hash
     */
    protected String getHashed()
    {
        return Utils.fromBytesToString(hashed);
    }

}
