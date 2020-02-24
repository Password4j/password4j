package com.password4j;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import com.lambdaworks.codec.Base64;
import com.lambdaworks.crypto.SCrypt;
import com.lambdaworks.crypto.SCryptUtil;


public class SCryptStrategy implements HashingStrategy
{
    private int resources = 8; // r

    private int workFactor = 2 << 14; // N

    private int parallelization = 1; // p

    public SCryptStrategy()
    {
        //
    }

    public SCryptStrategy(int resources, int workFactor, int parallelization)
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

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        SCryptStrategy otherStrategy = (SCryptStrategy) obj;
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
}
