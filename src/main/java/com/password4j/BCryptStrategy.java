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

import java.util.Arrays;

import org.mindrot.jbcrypt.BCrypt;


public class BCryptStrategy implements HashingStrategy
{
    public static final int DEFAULT_ROUNDS = 10;

    private int logRounds = DEFAULT_ROUNDS;

    public BCryptStrategy()
    {

    }

    public BCryptStrategy(int logRounds)
    {
        this();
        this.logRounds = logRounds;
    }

    @Override
    public Hash hash(String plain)
    {
        String salt = BCrypt.gensalt(logRounds, AlgorithmFinder.getSecureRandom());
        return hash(plain, salt);
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        return internalHash(plain, salt);
    }

    @Override
    public boolean check(String password, String hashed)
    {
        return BCrypt.checkpw(password, hashed);
    }

    private Hash internalHash(String plain, String salt)
    {
        try
        {
            String hash = BCrypt.hashpw(plain, salt);
            return new Hash(this, hash, salt);
        }
        catch (IllegalArgumentException iae)
        {
            String message = "Invalid specification with salt=" + salt + " and #rounds=`" + logRounds + "`";
            throw new BadParametersException(message, iae);
        }

    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        BCryptStrategy otherStrategy = (BCryptStrategy) obj;
        return this.logRounds == otherStrategy.logRounds;
    }

    @Override
    public String toString()
    {
        return getClass().getName() + Arrays.toString(new int[] { logRounds });
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }

}
