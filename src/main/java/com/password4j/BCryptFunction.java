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

import org.mindrot.jbcrypt.BCrypt;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


public class BCryptFunction extends AbstractHashingFunction
{
    private int logRounds;

    private static ConcurrentMap<Integer, BCryptFunction> instances = new ConcurrentHashMap<>();

    private BCryptFunction()
    {
        //
    }

    public BCryptFunction(int logRounds)
    {
        this();
        this.logRounds = logRounds;
    }

    public static BCryptFunction getInstance(int logRounds)
    {
        if (instances.containsKey(logRounds))
        {
            return instances.get(logRounds);
        }
        else
        {
            BCryptFunction function = new BCryptFunction(logRounds);
            instances.put(logRounds, function);
            return function;
        }
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

        BCryptFunction otherStrategy = (BCryptFunction) obj;
        return this.logRounds == otherStrategy.logRounds;
    }

    @Override
    public String toString()
    {
        return getClass().getName() + '[' + this.logRounds + ']';
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }

}
