package org.password4j.encryption;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.password4j.SaltGenerator;


public final class PBKDF2Strategy implements EncryptionStrategy
{

    private static final Logger LOG = LogManager.getLogger();

    private String algorithm = Algorithm.PBKDF2WithHmacSHA512.name();

    private int iterations = 10_000;

    private int length = Algorithm.PBKDF2WithHmacSHA512.getBits();

    public PBKDF2Strategy()
    {

    }

    public PBKDF2Strategy(int iterations, int length)
    {
        this();
        this.iterations = iterations;
        this.length = length;
    }

    public PBKDF2Strategy(String algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithm = algorithm;
    }

    public Encryption encrypt(char[] plain)
    {
        byte[] salt = SaltGenerator.generate();
        return encrypt(plain, salt);
    }

    @Override
    public Encryption encrypt(char[] plain, byte[] salt)
    {
        try
        {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            return new Encryption(Encryption.Status.OK, key.getEncoded(), salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            LOG.error("`{}` is not a valid algorithm", algorithm, nsae);
            return new Encryption(Encryption.Status.UNSUPPORTED, new byte[0], salt);
        }
        catch (InvalidKeySpecException iks)
        {
            LOG.error("Invalid specification with salt=`{}`, #iterations=`{}` and length=`{}`", salt, iterations, length, iks);
            return new Encryption(Encryption.Status.BAD_PARAMS, new byte[0], salt);
        }
    }

    public enum Algorithm
    {
        PBKDF2WithHmacSHA1(160), //
        PBKDF2WithHmacSHA224(224), //
        PBKDF2WithHmacSHA256(256), //
        PBKDF2WithHmacSHA384(384), //
        PBKDF2WithHmacSHA512(512);

        private int bits;

        Algorithm(int bits)
        {
            this.bits = bits;
        }

        public int getBits()
        {
            return bits;
        }
    }
}
