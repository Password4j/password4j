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
 * This interface declares the basic methods that
 * all the Cryptographic Hashing Functions (CHF) must have.
 * <p>
 * The two possible operations are
 * <ul>
 *     <li>hashing a plaintext password</li>
 *     <li>check if an hash is originated by a plaintext password</li>
 * </ul>
 * <p>
 * The purpose of this interface is encapsulate the logic of hashing
 * and checking of a CHF inside a class.
 *
 * @author David Bertoldi
 * @since 0.1.0
 */
public interface HashingFunction
{

    /**
     * Creates a {@link Hash} from a plaintext password.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * The salt is always generated randomly.
     * <p>
     * The generation of the salt is completely
     * responsibility of the implementing class.
     *
     * @param plainTextPassword the password to be hashed
     * @return a {@link Hash}
     * @see HashingFunction#hash(CharSequence, String)
     * @since 0.1.0
     */
    Hash hash(CharSequence plainTextPassword);

    /**
     * Creates a {@link Hash} from a plaintext password.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * The salt is always generated randomly.
     * <p>
     * The generation of the salt is completely
     * responsibility of the implementing class.
     *
     * @param plainTextPassword the password to be hashed as bytes array
     * @return a {@link Hash}
     * @see HashingFunction#hash(CharSequence, String)
     * @since 1.7.0
     */
    Hash hash(byte[] plainTextPassword);

    /**
     * Creates a {@link Hash} from a plaintext password and a salt.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * Some CHFs validate the format of the salt; if the validation
     * is not passed a {@link BadParametersException} is thrown.
     * The generation of the salt is completely
     * responsibility of the caller.
     *
     * @param plainTextPassword the password to be hashed
     * @param salt              the salt used in the hashing process
     * @return a {@link Hash}
     * @throws BadParametersException if the salt does not pass the validation of the CHF
     * @since 0.1.0
     */
    Hash hash(CharSequence plainTextPassword, String salt);

    /**
     * Creates a {@link Hash} from a plaintext password and a salt.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * Some CHFs validate the format of the salt; if the validation
     * is not passed a {@link BadParametersException} is thrown.
     * The generation of the salt is completely
     * responsibility of the caller.
     *
     * @param plainTextPassword the password to be hashed as bytes array
     * @param salt              the salt as bytes array used in the hashing process
     * @return a {@link Hash}
     * @throws BadParametersException if the salt does not pass the validation of the CHF
     * @since 1.7.0
     */
    Hash hash(byte[] plainTextPassword, byte[] salt);

    /**
     * Creates a {@link Hash} from a plaintext password and a salt.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * Some CHFs validate the format of the salt; if the validation
     * is not passed a {@link BadParametersException} is thrown.
     * The generation of the salt is completely
     * responsibility of the caller.
     *
     * @param plainTextPassword the password to be hashed
     * @param salt              the salt used in the hashing process
     * @param pepper            the pepper used int the hashing process
     * @return a {@link Hash}
     * @throws BadParametersException if the salt does not pass the validation of the CHF
     * @since 1.5.0
     */
    Hash hash(byte[] plainTextPassword, byte[] salt, CharSequence pepper);

    /**
     * Creates a {@link Hash} from a plaintext password and a salt.
     * Depending on the implementation, the hash may contain
     * the information about salt and pepper.
     * <p>
     * Some CHFs validate the format of the salt; if the validation
     * is not passed a {@link BadParametersException} is thrown.
     * The generation of the salt is completely
     * responsibility of the caller.
     *
     * @param plainTextPassword the password to be hashed as bytes array
     * @param salt              the salt as bytes array used in the hashing process
     * @param pepper            the pepper used int the hashing process
     * @return a {@link Hash}
     * @throws BadParametersException if the salt does not pass the validation of the CHF
     * @since 1.7.0
     */
    Hash hash(CharSequence plainTextPassword, String salt, CharSequence pepper);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password.
     * <p>
     * This method must be used when the salt is part
     * of the hash.
     * If the CHF expects a salt separated from the hash,
     * an {@link UnsupportedOperationException} is thrown.
     * <p>
     * In case the CHF expects a salt to be part of the hash,
     * if the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws UnsupportedOperationException if the CHF need a salt and it is not part of the hash
     * @throws BadParametersException        if the hash is not well-formed
     * @since 0.1.0
     */
    boolean check(CharSequence plainTextPassword, String hashed);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password.
     * <p>
     * This method must be used when the salt is part
     * of the hash.
     * If the CHF expects a salt separated from the hash,
     * an {@link UnsupportedOperationException} is thrown.
     * <p>
     * In case the CHF expects a salt to be part of the hash,
     * if the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password as bytes array
     * @param hashed            the hash as bytes array
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws UnsupportedOperationException if the CHF need a salt and it is not part of the hash
     * @throws BadParametersException        if the hash is not well-formed
     * @since 1.7.0
     */
    boolean check(byte[] plainTextPassword, byte[] hashed);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password and the salt.
     * <p>
     * This method must be used when the salt is not part
     * of the hash.
     * <p>
     * If the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @param salt              the salt used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws BadParametersException if the hash is not well-formed
     * @since 0.2.1
     */
    boolean check(CharSequence plainTextPassword, String hashed, String salt);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password and the salt.
     * <p>
     * This method must be used when the salt is not part
     * of the hash.
     * <p>
     * If the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password as bytes array
     * @param hashed            the hash as bytes array
     * @param salt              the salt as bytes array used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws BadParametersException if the hash is not well-formed
     * @since 1.7.0
     */
    boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password and the salt.
     * <p>
     * This method must be used when the salt is not part
     * of the hash.
     * <p>
     * If the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password
     * @param hashed            the hash
     * @param salt              the salt used to produce the hash
     * @param pepper            the pepper used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws BadParametersException if the hash is not well-formed
     * @since 1.5.0
     */
    boolean check(CharSequence plainTextPassword, String hashed, String salt, CharSequence pepper);

    /**
     * Checks if the CHF generated the hash starting from
     * the plaintext password and the salt.
     * <p>
     * This method must be used when the salt is not part
     * of the hash.
     * <p>
     * If the format of the hash is not valid (e.g. the CHF cannot
     * recognise a valid salt) a {@link BadParametersException}
     * is thrown.
     *
     * @param plainTextPassword the plaintext password as bytes array
     * @param hashed            the hash as bytes array
     * @param salt              the salt as bytes array used to produce the hash
     * @param pepper            the pepper used to produce the hash
     * @return true if the hash is generated from the plaintext; false otherwise
     * @throws BadParametersException if the hash is not well-formed
     * @since 1.5.0
     */
    boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt, CharSequence pepper);
}
