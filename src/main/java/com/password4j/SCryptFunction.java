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

import com.lambdaworks.codec.Base64;
import com.lambdaworks.crypto.SCrypt;
import com.lambdaworks.crypto.SCryptUtil;

import java.security.GeneralSecurityException;
import java.util.Arrays;


public class SCryptFunction implements HashingFunction
{
    public static final int DEFAULT_RES = 8;

    public static final int DEFAULT_WORKFACTOR = 2 << 14;

    public static final int DEFAULT_PARALLELIZATION = 1;

    private int resources = DEFAULT_RES; // r

    private int workFactor = DEFAULT_WORKFACTOR; // N

    private int parallelization = DEFAULT_PARALLELIZATION; // p

    public SCryptFunction()
    {
        //
    }

    public SCryptFunction(int resources, int workFactor, int parallelization)
    {
        this();
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
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
            byte[] saltAsBytes = salt.getBytes();
            byte[] derived = SCrypt.scrypt(plain.getBytes(), saltAsBytes, workFactor, resources, parallelization, 32);
            String params = Long.toString((long) (log2(workFactor) << 16 | resources << 8 | parallelization), 16);
            StringBuilder sb = new StringBuilder((saltAsBytes.length + derived.length) * 2);
            sb.append("$s0$").append(params).append('$');
            sb.append(Base64.encode(saltAsBytes)).append('$');
            sb.append(Base64.encode(derived));
            return new Hash(this, sb.toString(), salt);
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
        return SCryptUtil.check(plain, hashed);
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
        return getClass().getName() + Arrays.toString(new int[] { workFactor, resources, parallelization });
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
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
