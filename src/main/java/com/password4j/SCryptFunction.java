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

import com.lambdaworks.crypto.SCrypt;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


public class SCryptFunction extends AbstractHashingFunction
{

    private int resources; // r

    private int workFactor; // N

    private int parallelization; // p

    private static ConcurrentMap<String, SCryptFunction> instances = new ConcurrentHashMap<>();

    private SCryptFunction()
    {
        //
    }

    protected SCryptFunction(int resources, int workFactor, int parallelization)
    {
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
    }

    public static SCryptFunction getInstanceFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            long params = Long.parseLong(parts[2], 16);
            int workFactor = (int) Math.pow(2.0D, (double) (params >> 16 & 65535L));
            int resources = (int) params >> 8 & 255;
            int parallelization = (int) params & 255;

            return SCryptFunction.getInstance(resources, workFactor, parallelization);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    public static SCryptFunction getInstance(int resources, int workFactor, int parallelization)
    {
        String key = getUID(resources, workFactor, parallelization);
        if (instances.containsKey(key))
        {
            return instances.get(key);
        }
        else
        {
            SCryptFunction function = new SCryptFunction(resources, workFactor, parallelization);
            instances.put(key, function);
            return function;
        }
    }

    @Override
    public Hash hash(String plain)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plain, new String(salt));
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        try
        {
            byte[] saltAsBytes = salt.getBytes(StandardCharsets.UTF_8);
            byte[] derived = SCrypt.scrypt(plain.getBytes(StandardCharsets.UTF_8), saltAsBytes, workFactor, resources, parallelization, 64);
            String params = Long.toString(log2(workFactor) << 16 | resources << 8 | parallelization, 16);
            String sb = "$s0$" + params + '$' +
                    Base64.getEncoder().encodeToString(saltAsBytes) + '$' +
                    Base64.getEncoder().encodeToString(derived);
            return new Hash(this, sb, salt);
        }
        catch (IllegalArgumentException | GeneralSecurityException e)
        {
            String message = "Invalid specification with salt=" + salt + ", N=`" + workFactor + ", r=`" + resources + " and p=`" + parallelization + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(String plain, String hashed)
    {
        try
        {
            String[] parts = hashed.split("\\$");
            if (parts.length == 5 && parts[1].equals("s0"))
            {
                long params = Long.parseLong(parts[2], 16);
                byte[] salt = com.lambdaworks.codec.Base64.decode(parts[3].toCharArray());
                byte[] derived0 = com.lambdaworks.codec.Base64.decode(parts[4].toCharArray());
                int N = (int) Math.pow(2.0D, (double) (params >> 16 & 65535L));
                int r = (int) params >> 8 & 255;
                int p = (int) params & 255;
                byte[] derived1 = SCrypt.scrypt(plain.getBytes(StandardCharsets.UTF_8), salt, N, r, p, 64);
                if (derived0.length != derived1.length)
                {
                    return false;
                }
                else
                {
                    int result = 0;

                    for (int i = 0; i < derived0.length; ++i)
                    {
                        result |= derived0[i] ^ derived1[i];
                    }

                    return result == 0;
                }
            }
            else
            {
                throw new BadParametersException("Invalid hashed value");
            }
        }
        catch (GeneralSecurityException var14)
        {
            throw new IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?");
        }
    }

    public long getRequiredBytes()
    {
        return 128L * workFactor * resources * parallelization;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        SCryptFunction otherStrategy = (SCryptFunction) obj;
        return this.workFactor == otherStrategy.workFactor //
                && this.resources == otherStrategy.resources //
                && this.parallelization == otherStrategy.parallelization;
    }

    @Override
    public String toString()
    {
        return getClass().getName() + '[' + getUID(this.resources, this.workFactor, this.parallelization) + ']';
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(resources, workFactor, parallelization);
    }

    protected static String getUID(int resources, int workFactor, int parallelization)
    {
        return String.valueOf(resources + '|' + workFactor + '|' + parallelization);
    }

    private static int log2(int n)
    {
        int log = 0;
        if ((n & -65536) != 0)
        {
            n >>>= 16;
            log = 16;
        }
        if (n >= 256)
        {
            n >>>= 8;
            log += 8;
        }
        if (n >= 16)
        {
            n >>>= 4;
            log += 4;
        }
        if (n >= 4)
        {
            n >>>= 2;
            log += 2;
        }
        return log + (n >>> 1);
    }
}
