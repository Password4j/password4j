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

public class HashChecker
{
    private String hash;

    private String pepper;

    private String plain;

    private HashChecker()
    {
        //
    }

    HashChecker(String hash, String plain)
    {
        this.hash = hash;
        this.plain = plain;
    }

    public HashChecker addPepper(String pepper)
    {
        this.pepper = pepper;
        return this;
    }

    public boolean with(HashingFunction hashingFunction)
    {
        Hash internalHash = new Hash(hashingFunction, hash, null);
        internalHash.setPepper(pepper);

        return internalHash.check(plain);
    }

    public boolean withPBKDF2()
    {
        PBKDF2Function pbkdf2 = PBKDF2Function.getInstanceFromHash(hash);
        return with(pbkdf2);
    }

    public boolean withSCrypt()
    {
        SCryptFunction scrypt = SCryptFunction.getInstanceFromHash(hash);
        return with(scrypt);
    }

    public boolean withBCrypt()
    {
        return with(new BCryptFunction());
    }


}
