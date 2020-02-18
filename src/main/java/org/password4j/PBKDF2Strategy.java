package org.password4j;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;


public final class PBKDF2Strategy implements EncryptionStrategy
{

    private static final Logger LOG = LogManager.getLogger();

    private static final String ALGORITHM_PREFIX = "PBKDF2WithHmac";

    private String hashFunction = "SHA512";

    private int iterations = 10_000;

    private int length = 512;

    private byte[] salt = new byte[64];

    public PBKDF2Strategy()
    {
        createSalt();
    }


    public PBKDF2Strategy(int iterations, int length)
    {
        this();
        this.iterations = iterations;
        this.length = length;
    }

    public PBKDF2Strategy(String hashFunction, int iterations, int length)
    {
        this(iterations, length);
        this.hashFunction = hashFunction;
    }

    private void createSalt()
    {
        Random random = new SecureRandom();
        random.nextBytes(this.salt);
    }


    public byte[] encrypt(char[] plain)
    {
        try
        {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(getAlgorithm());
            PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            return key.getEncoded();
        }
        catch (NoSuchAlgorithmException nsae)
        {
            LOG.error("`{}` is not a valid algorithm", getAlgorithm(), nsae);
            return new byte[0];
        }
        catch (InvalidKeySpecException iks)
        {
            LOG.error("Invalid specification with plain=`{}`, salt=`{}`, #iterations=`{}` and length=`{}`", coverPassword(plain), salt, iterations, length, iks);
            return new byte[0];
        }
    }

    private String getAlgorithm()
    {
        return ALGORITHM_PREFIX + this.hashFunction;
    }

    private String coverPassword(char[] plain)
    {
        char[] tmp = new char[plain == null ? 0 : plain.length];
        Arrays.fill(tmp, '*');
        return String.copyValueOf(tmp);
    }

    @Override
    public String toString()
    {
        return "PBKDF2Strategy{" +
                "algorithm='" + getAlgorithm() + '\'' +
                ", iterations=" + iterations +
                ", length=" + length +
                ", salt=" + Arrays.toString(salt) +
                '}';
    }
}
