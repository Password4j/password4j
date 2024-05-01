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
 * This class represents the result of the password verification process
 * along with the generated {@link Hash}.
 * <p>
 * If the verification passed a new hash is always provided.
 *
 * @author David Bertoldi
 * @since 1.3.0
 */
public class HashUpdate
{
    public static final HashUpdate UNVERIFIED = new HashUpdate();

    private Hash hash;

    private boolean updated;

    private HashUpdate()
    {
        //
    }

    /**
     * @param hash the new hash
     * @throws BadParametersException if hash is null but verified is true
     * @since 1.3.0
     */
    public HashUpdate(Hash hash)
    {
        this.hash = hash;
    }

    /**
     * @param hash    the new hash
     * @param updated flag for updated hash
     * @throws BadParametersException if hash is null but verified is true
     * @since 1.7.0
     */
    public HashUpdate(Hash hash, boolean updated)
    {
        this(hash);
        this.updated = updated;
    }

    /**
     * Returns the hash generated after a verification + update
     * process.
     * <p>
     * It is never null if the hash is {@link #isVerified()}
     * return true.
     *
     * @return the regenerated hash
     * @since 1.3.0
     */
    public Hash getHash()
    {
        return this.hash;
    }

    /**
     * Returns the result of the verification process.
     *
     * @return true if the verification process was successful
     * @since 1.3.0
     */
    public boolean isVerified()
    {
        return hash != null;
    }

    /**
     * True if the update process changed the original hash due to changes on parameters.
     * Changing the algorithms always set this flag to true.
     *
     * @return true if the hash was updated
     * @since 1.7.0
     */
    public boolean isUpdated()
    {
        return updated;
    }
}
