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
 * @author David Bertoldi
 * @since 1.3.0
 */
public class HashUpdater
{

    protected HashChecker hashChecker;

    protected HashBuilder hashBuilder;

    private boolean force;

    HashUpdater(HashChecker hashChecker, HashBuilder hashBuilder)
    {
        this.hashChecker = hashChecker;
        this.hashBuilder = hashBuilder;
    }

    /**
     * Check if the previously given hash was produced from the given plain text password
     * with a specific implementation of {@link HashingFunction}. If the verification
     * passes a new hash is generated with the new implementation of {@link HashingFunction}.
     *
     * @param oldHashingFunction the original CHF used to produce the actual hash
     * @param newHashingFunction the new CHF to be used the new hash
     * @return the result of the password verification along with the new hash
     * @see HashUpdate
     * @since 1.3.0
     */
    public HashUpdate with(HashingFunction oldHashingFunction, HashingFunction newHashingFunction)
    {
        if (oldHashingFunction == null)
        {
            throw new BadParametersException("Starting hashing function cannot be null.");
        }
        if (newHashingFunction == null)
        {
            throw new BadParametersException("New hashing function cannot be null.");
        }

        boolean toBeUpdated = force || //
                !oldHashingFunction.equals(newHashingFunction) //
                || hashBuilder.salt != null //
                || hashBuilder.pepper != null;

        if (hashChecker.with(oldHashingFunction))
        {
            if (toBeUpdated)
            {
                Hash hash = this.hashBuilder.with(newHashingFunction);
                return new HashUpdate(hash, true);
            }
            else
            {
                Hash hash = new Hash(oldHashingFunction, hashChecker.hashed, null, hashChecker.salt);
                return new HashUpdate(hash, false);
            }

        }
        else
        {
            return HashUpdate.UNVERIFIED;
        }
    }

    /**
     * Adds new cryptographic salt to be applied in the hash update.
     *
     * @param salt cryptographic salt
     * @return this builder
     * @since 1.3.0
     */
    public HashUpdater addNewSalt(String salt)
    {
        this.hashBuilder.addSalt(salt);
        return this;
    }

    /**
     * Adds new cryptographic salt to be applied in the hash update.
     *
     * @param saltAsBytes cryptographic salt as bytes array
     * @return this builder
     * @since 1.3.0
     */
    public HashUpdater addNewSalt(byte[] saltAsBytes)
    {
        this.hashBuilder.addSalt(saltAsBytes);
        return this;
    }

    /**
     * Add a random cryptographic salt in the hash update process.
     * The salt is applied differently depending on the new chosen algorithm.
     *
     * @return this builder
     * @see SaltGenerator#generate() for more information about the length of the product
     * @since 1.3.0
     */
    public HashUpdater addNewRandomSalt()
    {
        this.hashBuilder.addRandomSalt();
        return this;
    }

    /**
     * Add a random cryptographic salt in the hash update process with a given length.
     * The salt is applied differently depending on the new chosen algorithm.
     *
     * @param length the length of the salt produced
     * @return this builder
     * @throws BadParametersException if the length is non-positive
     * @see SaltGenerator#generate() for more information about the length of the product
     * @since 1.3.0
     */
    public HashUpdater addNewRandomSalt(int length)
    {
        this.hashBuilder.addRandomSalt(length);
        return this;
    }

    /**
     * Concatenates the pepper configured in your `psw4j.properties` file with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the new algorithm.
     *
     * @return this builder
     * @see PepperGenerator#get()
     * @since 1.3.0
     */
    public HashUpdater addNewPepper()
    {
        this.hashBuilder.addPepper();
        return this;
    }

    /**
     * Concatenates the provided string with the plain text password.
     * The produced sequence (in the form {@code pepper+password}) is processed by the new algorithm.
     *
     * @param pepper cryptographic pepper
     * @return this builder
     * @since 1.3.0
     */
    public HashUpdater addNewPepper(CharSequence pepper)
    {
        this.hashBuilder.addPepper(pepper);
        return this;
    }

    /**
     * Forces the update of the hash even if function, salt and pepper did not change.
     * This can be helpful with algorithm like Bcrypt that generates their own salt.
     *
     * @return this builder
     * @since 1.7.0
     */
    public HashUpdater forceUpdate()
    {
        this.force = true;
        return this;
    }

    /**
     * Hashes the previously given plain text password
     * with {@link PBKDF2Function}.
     * <p>
     * This method read the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getPBKDF2Instance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withPBKDF2()
    {
        return withPBKDF2(AlgorithmFinder.getPBKDF2Instance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link PBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getPBKDF2Instance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withPBKDF2(HashingFunction newHashingFunction)
    {
        return with(AlgorithmFinder.getPBKDF2Instance(), newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link CompressedPBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getCompressedPBKDF2Instance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withCompressedPBKDF2()
    {
        CompressedPBKDF2Function pbkdf2 = AlgorithmFinder.getCompressedPBKDF2Instance();
        return withCompressedPBKDF2(pbkdf2);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link CompressedPBKDF2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getCompressedPBKDF2Instance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withCompressedPBKDF2(HashingFunction newHashingFunction)
    {
        CompressedPBKDF2Function pbkdf2 = CompressedPBKDF2Function.getInstanceFromHash(hashChecker.getHashed());
        return with(pbkdf2, newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BcryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getBcryptInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withBcrypt()
    {
        return withBcrypt(AlgorithmFinder.getBcryptInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BcryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getBcryptInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withBcrypt(HashingFunction newHashingFunction)
    {
        return with(BcryptFunction.getInstanceFromHash(hashChecker.getHashed()), newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link ScryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getScryptInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withScrypt()
    {
        return withScrypt(AlgorithmFinder.getScryptInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link ScryptFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getScryptInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.3.0
     */
    public HashUpdate withScrypt(HashingFunction newHashingFunction)
    {
        return with(ScryptFunction.getInstanceFromHash(hashChecker.getHashed()), newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link MessageDigestFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getMessageDigestInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.4.0
     */
    public HashUpdate withMessageDigest()
    {
        return withMessageDigest(AlgorithmFinder.getMessageDigestInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link MessageDigestFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getMessageDigestInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.4.0
     */
    public HashUpdate withMessageDigest(HashingFunction newHashingFunction)
    {
        return with(AlgorithmFinder.getMessageDigestInstance(), newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link Argon2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getArgon2Instance() ()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.5.0
     */
    public HashUpdate withArgon2()
    {
        return withArgon2(AlgorithmFinder.getArgon2Instance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link Argon2Function}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getArgon2Instance() ()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.5.0
     */
    public HashUpdate withArgon2(HashingFunction newHashingFunction)
    {
        return with(Argon2Function.getInstanceFromHash(hashChecker.getHashed()), newHashingFunction);
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BalloonHashingFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getBalloonHashingInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.5.0
     */
    public HashUpdate withBalloonHashing()
    {
        return withBalloonHashing(AlgorithmFinder.getBalloonHashingInstance());
    }

    /**
     * Hashes the previously given plain text password
     * with {@link BalloonHashingFunction}.
     * <p>
     * This method reads the configurations in the `psw4j.properties` file. If no configuration is found,
     * then the default parameters are used.
     * <p>
     * Finally calls {@link #with(HashingFunction, HashingFunction)}
     *
     * @return the result of the verification with the new hash
     * @see AlgorithmFinder#getBalloonHashingInstance()
     * @see #with(HashingFunction, HashingFunction)
     * @since 1.5.0
     */
    public HashUpdate withBalloonHashing(HashingFunction newHashingFunction)
    {
        return with(AlgorithmFinder.getBalloonHashingInstance(), newHashingFunction);
    }
}
