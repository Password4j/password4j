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

import com.password4j.types.Hmac;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

public class HOTPGenerator extends OTPGenerator
{
    private static final Map<String, HOTPGenerator> INSTANCES = new ConcurrentHashMap<>();

    HOTPGenerator(int length)
    {
        super(Hmac.SHA1, length);
    }

    public static HOTPGenerator getInstance(int length)
    {
        checkLength(length);
        String key = getUID(length);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            HOTPGenerator generator = new HOTPGenerator(length);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    private static String getUID(int length)
    {
        return String.valueOf(length);
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '(' + toString(this.length) + ')';
    }

    protected static String toString(int length)
    {
        return "l=" + length;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(length);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        HOTPGenerator other = (HOTPGenerator) obj;
        return this.length == other.length;
    }

}