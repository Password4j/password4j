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
     */
    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        return check(plainTextPassword, hashed);
    }
}
