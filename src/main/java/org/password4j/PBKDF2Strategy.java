package org.password4j;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Hex;


public final class PBKDF2Strategy implements HashingStrategy
{
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

    public Hash hash(char[] plain)
    {
        byte[] salt = SaltGenerator.generate();
        return hash(plain, salt);
    }

    @Override
    public Hash hash(char[] plain, byte[] salt)
    {
        try
        {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
            PBEKeySpec spec = new PBEKeySpec(plain, salt, iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            return new Hash(this, key.getEncoded(), salt).readResultWith(Hex::encodeHexString);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + Arrays
                    .toString(salt) + ", #iterations=`" + iterations + "` and length=`" + length + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(char[] password, byte[] hashed)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean check(char[] password, byte[] hashed, byte[] salt)
    {
        byte[] result = hash(password, salt).getResult();
        return slowEquals(result, hashed);
    }



    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line
     * system using a timing attack and then attacked off-line.
     *
     * @param a the first byte array
     * @param b the second byte array
     * @return true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
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
