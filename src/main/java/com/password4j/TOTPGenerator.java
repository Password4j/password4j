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

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import com.password4j.types.Hmac;


public class TOTPGenerator extends OTPGenerator
{

    private static final Map<String, TOTPGenerator> INSTANCES = new ConcurrentHashMap<>();

    Duration duration;

    TOTPGenerator(Hmac hmac, Duration duration, int length)
    {
        super(hmac, length);
        this.duration = duration;
    }

    public String generate(byte[] key, Instant instant)
    {
        return generate(key, instant.toEpochMilli() / duration.toMillis());
    }


    public static TOTPGenerator getInstance(Hmac hmac, Duration duration, int length)
    {
        checkLength(length);
        String key = getUID(hmac, duration, length);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            TOTPGenerator generator = new TOTPGenerator(hmac, duration, length);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    private static String getUID(Hmac hmac, Duration duration, int length)
    {
        return hmac.name() + '|' + duration.toMillis() + '|' + length;
    }

    public Duration getDuration()
    {
        return duration;
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '(' + toString(hmac, duration, length) + ')';
    }

    protected static String toString(Hmac hmac, Duration duration, int length)
    {
        return "a=" + hmac.name().toUpperCase() + ", d=" + duration.toMillis() + ", l=" + length;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(hmac, duration, length);
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        TOTPGenerator other = (TOTPGenerator) obj;
        return this.length == other.length &&
                this.duration.equals(other.duration) &&
                this.hmac.equals(other.hmac);
    }





}