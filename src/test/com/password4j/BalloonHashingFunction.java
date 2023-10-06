/*
 *  (C) Copyright 2023 Password4j (http://password4j.com/).
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;

/**
 * @author David Bertoldi
 * @since 1.8.0
 */
public class BalloonHashingFunction extends MessageDigestFunction
{

    private static final Map<String, BalloonHashingFunction> INSTANCES = new ConcurrentHashMap<>();
    private static final int DEFAULT_DELTA = 3;
    private final int spaceCost;

    private final int timeCost;

    private final int parallelism;

    private final int delta;

    BalloonHashingFunction(String algorithm, SaltOption saltOption, int spaceCost, int timeCost,  int parallelism, int delta)
    {
        super(algorithm, saltOption);
        this.spaceCost = spaceCost;
        this.timeCost = timeCost;
        this.parallelism = parallelism;
        this.delta = delta;
    }


    public static BalloonHashingFunction getInstance(String algorithm, SaltOption saltOption, int spaceCost, int timeCost,  int parallelism, int delta)
    {
        String key = getUID(algorithm, saltOption, spaceCost, timeCost, parallelism, delta);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            BalloonHashingFunction function = new BalloonHashingFunction(algorithm, saltOption, spaceCost, timeCost, parallelism, delta);
            INSTANCES.put(key, function);
            return function;
        }
    }

    public static BalloonHashingFunction getInstance(String algorithm, int spaceCost, int timeCost,  int parallelism)
    {
        return getInstance(algorithm, DEFAULT_SALT_OPTION, spaceCost, timeCost, parallelism, DEFAULT_DELTA);
    }

    @Override
    public Hash hash(CharSequence plainTextPassword)
    {
        return null;
    }

    @Override
    public Hash hash(byte[] plainTextPassword)
    {
        return null;
    }

    @Override
    public Hash hash(CharSequence plainTextPassword, String salt)
    {
        return hash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt));
    }

    @Override
    public Hash hash(byte[] plainTextPassword, byte[] salt)
    {
        if (salt == null || salt.length < 4)
        {
            throw new BadParametersException("Salt must be at least 4 bytes long. Provided " + Arrays.toString(salt));
        }
        return internalHash(plainTextPassword, salt);
    }

    @Override
    protected Hash internalHash(byte[] plainTextPassword, byte[] salt)
    {
        ExecutorService service = Executors.newFixedThreadPool(parallelism);
        List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < parallelism; i++)
        {
            byte[] parallelSalt = Utils.append(salt, Utils.longToLittleEndian((i + 1)));
            Future<byte[]> future = service.submit(() -> balloonM(plainTextPassword, parallelSalt));

            futures.add(future);
        }

        try
        {
            byte[] output = (byte[]) futures.get(0).get();
            for (Future<?> f : futures)
            {
                //byte[] f.get();
            }
        }
        catch (InterruptedException | ExecutionException e)
        {
            Thread.currentThread().interrupt();
        }

        service.shutdownNow();

        return null;
    }

    private byte[] balloonM(byte[] plainTextPassword, byte[] salt)
    {
        return null;
    }



    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return false;
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed)
    {
        return false;
    }

    private static String getUID(String algorithm, SaltOption saltOption, int spaceCost, int timeCost,  int parallelism, int delta)
    {
        return MessageDigestFunction.getUID(algorithm, saltOption) + '|' + spaceCost + '|' + timeCost + '|' + parallelism + '|' + delta;
    }
}
