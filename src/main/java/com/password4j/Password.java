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


public class Password
{

    private String plain;

    private String salt;

    private String pepper;

    private Password()
    {
        //
    }

    private Password(String plain)
    {
        this();
        this.plain = plain;
    }

    public static Password hash(String plain)
    {
        if (plain == null)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return new Password(plain);
    }

    public Password addSalt(String salt)
    {
        this.salt = salt;
        return this;
    }

    public Password addRandomSalt()
    {
        this.salt = new String(SaltGenerator.generate());
        return this;
    }

    public Password addRandomSalt(int length)
    {
        if (length <= 0)
        {
            throw new BadParametersException("Salt cannot have a non-positive length");
        }
        else
        {
            this.salt = new String(SaltGenerator.generate(length));
        }
        return this;
    }

    public Password addPepper()
    {
        this.pepper = PepperGenerator.get();
        return this;
    }

    public Password addPepper(String pepper)
    {
        this.pepper = pepper;
        return this;
    }


    public Hash with(HashingStrategy hashingStrategy)
    {
        String peppered = plain;
        if (StringUtils.isNotEmpty(this.pepper))
        {
            peppered = this.pepper + peppered;
        }

        Hash hash;
        if (StringUtils.isEmpty(this.salt))
        {
            hash = hashingStrategy.hash(peppered);
        }
        else
        {
            hash = hashingStrategy.hash(peppered, salt);
        }

        hash.setPepper(pepper);
        return hash;
    }

    public Hash withPBKDF2()
    {
        return with(AlgorithmFinder.getPBKDF2Instance());
    }

    public Hash withBCrypt()
    {
        return with(AlgorithmFinder.getBCryptInstance());
    }

    public Hash withSCrypt()
    {
        return with(AlgorithmFinder.getSCryptInstance());
    }


}
