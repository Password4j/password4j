/*
 *  (C) Copyright 2022 Password4j (http://password4j.com/).
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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


public class SecretKeyGenerator
{

    private static final ConcurrentMap<String, SecretKeyGenerator> INSTANCES = new ConcurrentHashMap<>();

    private boolean randomly;

    private String source;

    int length;
    SecretKeyGenerator(int length)
    {
        this.length = length;
    }

    public SecretKeyGenerator randomly()
    {
        this.randomly = true;
        return this;
    }

    public SecretKeyGenerator fromSource(String source)
    {
        this.source = source;
        return this;
    }

    public String withBase32()
    {
        if (randomly)
        {
            Random random = AlgorithmFinder.getSecureRandom();

        }
        return null;
    }

    public static SecretKeyGenerator getInstance(int length)
    {
        String key = getUID(length);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            SecretKeyGenerator function = new SecretKeyGenerator(length);
            INSTANCES.put(key, function);
            return function;
        }
    }

    private static String getUID(int length)
    {
        return String.valueOf(length);
    }







}
