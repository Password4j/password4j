package org.password4j.encryption;

import java.security.GeneralSecurityException;

import org.password4j.SaltGenerator;

import com.lambdaworks.codec.Base64;
import com.lambdaworks.crypto.SCrypt;


public class ScryptStrategy implements EncryptionStrategy
{

    private int resources = 16; // r

    private int workFactor = 2; // N

    private int parallelization = Runtime.getRuntime().availableProcessors(); // p

    private long requiredBytes = 128L * workFactor * resources * parallelization;

    public ScryptStrategy()
    {
        //
    }
    
    public ScryptStrategy(int resources, int workFactor, int parallelization)
    {
        this();
        this.resources = resources;
        this.workFactor = workFactor;
        this.parallelization = parallelization;
    }

    @Override
    public Encryption encrypt(char[] plain)
    {
        return encrypt(plain, SaltGenerator.generate(16));
    }

    @Override
    public Encryption encrypt(char[] plain, byte[] salt)
    {
        try
        {
            byte[] derived = SCrypt.scrypt(new String(plain).getBytes(), salt, workFactor, resources, parallelization, 32);
            String params = Long.toString((long) (log2(workFactor) << 16 | resources << 8 | parallelization), 16);
            StringBuilder sb = new StringBuilder((salt.length + derived.length) * 2);
            sb.append("$s0$").append(params).append('$');
            sb.append(Base64.encode(salt)).append('$');
            sb.append(Base64.encode(derived));
            return new Encryption(Encryption.Status.OK, sb.toString().getBytes(), salt);
        }
        catch (GeneralSecurityException var9)
        {
            return new Encryption(Encryption.Status.UNSUPPORTED, new byte[0], salt);
        }
    }

    public long getRequiredBytes()
    {
        return requiredBytes;
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
