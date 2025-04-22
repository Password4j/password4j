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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

/**
 * Class containing the implementation of Balloon hashing function and its parameters.
 *
 * @author David Bertoldi
 * @since 1.8.0
 */
public class BalloonHashingFunction extends AbstractHashingFunction
{

    private static final Map<String, BalloonHashingFunction> INSTANCES = new ConcurrentHashMap<>();
    private static final int DEFAULT_DELTA = 3;

    private final String algorithm;
    private final int spaceCost;
    private final int timeCost;
    private final int parallelism;
    private final int delta;
    private ExecutorService service;

    BalloonHashingFunction(String algorithm, int spaceCost, int timeCost, int parallelism, int delta)
    {
        this.algorithm = algorithm;
        this.spaceCost = spaceCost;
        this.timeCost = timeCost;
        this.parallelism = parallelism;
        this.delta = delta;
        if (parallelism > 1)
        {
            this.service = Utils.createExecutorService();
        }

    }


    public static BalloonHashingFunction getInstance(String algorithm, int spaceCost, int timeCost, int parallelism, int delta)
    {
        String key = getUID(algorithm, spaceCost, timeCost, parallelism, delta);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            BalloonHashingFunction function = new BalloonHashingFunction(algorithm, spaceCost, timeCost, parallelism, delta);
            INSTANCES.put(key, function);
            return function;
        }
    }

    public static BalloonHashingFunction getInstance(String algorithm, int spaceCost, int timeCost, int parallelism)
    {
        return getInstance(algorithm, spaceCost, timeCost, parallelism, DEFAULT_DELTA);
    }

    private static String getUID(String algorithm, int spaceCost, int timeCost, int parallelism, int delta)
    {
        return algorithm + '|' + spaceCost + '|' + timeCost + '|' + parallelism + '|' + delta;
    }

    protected static String toString(String algorithm, int spaceCost, int timeCost, int parallelism, int delta)
    {
        return "a=" + algorithm + ", s=" + spaceCost + ", t=" + timeCost + ", p=" + parallelism + ", d=" + delta;
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
        return internalHash(plainTextPassword, salt);
    }

    protected Hash internalHash(byte[] plainTextPassword, byte[] salt)
    {

        byte[] output;

        if (parallelism == 1)
        {
            byte[] parallelSalt = Utils.append(salt, Utils.longToLittleEndian((1)));
            MessageDigest messageDigest = getMessageDigest();
            output = balloon(messageDigest, plainTextPassword, parallelSalt);
            output = hashFunc(messageDigest, plainTextPassword, salt, output);
        }
        else if (parallelism > 1)
        {

            List<Future<?>> futures = new ArrayList<>();

            for (int i = 0; i < parallelism; i++)
            {
                byte[] parallelSalt = Utils.append(salt, Utils.longToLittleEndian((i + 1)));
                Future<byte[]> future = service.submit(() -> balloon(getMessageDigest(), plainTextPassword, parallelSalt));

                futures.add(future);
            }

            MessageDigest messageDigest = getMessageDigest();
            output = new byte[messageDigest.getDigestLength()];

            try
            {
                byte[] tmp;
                output = (byte[]) futures.get(0).get();
                for (int f = 1; f < futures.size(); f++)
                {
                    tmp = ((byte[]) futures.get(f).get());

                    for (int i = 0; i < output.length; i++)
                    {
                        output[i] ^= tmp[i];
                    }

                }
            }
            catch (InterruptedException | ExecutionException e)
            {
                Thread.currentThread().interrupt();
            }


            output = hashFunc(messageDigest, plainTextPassword, salt, output);
        }
        else
        {
            output = balloon(getMessageDigest(), plainTextPassword, salt);
        }

        return new Hash(this, Utils.toHex(output), output, salt);
    }

    protected MessageDigest getMessageDigest()
    {
        try
        {
            return MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            throw new UnsupportedOperationException("`" + algorithm + "` is not supported by your system.", nsae);
        }
    }

    private byte[] balloon(MessageDigest messageDigest, byte[] plainTextPassword, byte[] salt)
    {
        List<byte[]> buffer = new ArrayList<>();
        buffer.add(hashFunc(messageDigest, 0, plainTextPassword, salt));

        int cnt = 1;

        cnt = expand(messageDigest, buffer, cnt);
        mix(messageDigest, buffer, cnt, salt);
        return extract(buffer);
    }

    private int expand(MessageDigest messageDigest, List<byte[]> buffer, int cnt)
    {
        int newCnt = cnt;
        for (int i = 1; i < spaceCost; i++)
        {
            buffer.add(hashFunc(messageDigest, newCnt, buffer.get(i - 1)));
            newCnt += 1;
        }
        return newCnt;
    }

    private void mix(MessageDigest messageDigest, List<byte[]> buffer, int cnt, byte[] salt)
    {
        int newCnt = cnt;
        for (int t = 0; t < timeCost; t++)
        {
            for (int s = 0; s < spaceCost; s++)
            {
                buffer.set(s, hashFunc(messageDigest, newCnt, get(buffer, s - 1), get(buffer, s)));
                newCnt += 1;

                for (int d = 0; d < delta; d++)
                {
                    byte[] indexBlock = hashFunc(messageDigest, t, s, d);
                    int other = Utils.bytesToInt(hashFunc(messageDigest, newCnt, salt, indexBlock)).mod(BigInteger.valueOf(spaceCost)).intValue();
                    newCnt += 1;
                    buffer.set(s, hashFunc(messageDigest, newCnt, buffer.get(s), get(buffer, other)));
                    newCnt += 1;
                }
            }
        }
    }

    private byte[] extract(List<byte[]> buffer)
    {
        return buffer.get(buffer.size() - 1);
    }

    private byte[] get(List<byte[]> buffer, int position)
    {
        if (position < 0)
        {
            return buffer.get(buffer.size() + position);
        }
        return buffer.get(position);
    }

    private byte[] hashFunc(MessageDigest md, Object... args)
    {
        byte[] t = new byte[0];

        for (Object arg : args)
        {
            if (arg instanceof Integer)
            {
                t = Utils.append(t, Utils.intToLittleEndianBytes((Integer) arg, 8));
            }
            else if (arg instanceof CharSequence)
            {
                t = Utils.append(t, Utils.fromCharSequenceToBytes((CharSequence) arg));
            }
            else if (arg instanceof byte[])
            {
                t = Utils.append(t, (byte[]) arg);
            }
        }

        return md.digest(t);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed)
    {
        return check(plainTextPassword, hashed, null);
    }

    @Override
    public boolean check(CharSequence plainTextPassword, String hashed, String salt)
    {
        Hash hash = internalHash(Utils.fromCharSequenceToBytes(plainTextPassword), Utils.fromCharSequenceToBytes(salt));
        return slowEquals(hash.getResult(), hashed);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed)
    {
        return check(plainTextPassword, new byte[0], hashed, null);
    }

    @Override
    public boolean check(byte[] plainTextPassword, byte[] hashed, byte[] salt)
    {
        Hash hash = internalHash(plainTextPassword, salt);
        return slowEquals(hash.getResultAsBytes(), hashed);
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
            return true;
        if (!(o instanceof BalloonHashingFunction))
            return false;
        BalloonHashingFunction other = (BalloonHashingFunction) o;
        return algorithm.equals(other.algorithm) //
                && spaceCost == other.spaceCost //
                && timeCost == other.timeCost //
                && parallelism == other.parallelism //
                && delta == other.delta;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(algorithm, spaceCost, timeCost, parallelism, delta);
    }

    @Override
    public String toString()
    {
        return getClass().getSimpleName() + '[' + toString(algorithm, spaceCost, timeCost, parallelism, delta) + ']';
    }
}
