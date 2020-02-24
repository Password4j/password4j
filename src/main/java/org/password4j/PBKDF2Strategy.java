package org.password4j;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


public final class PBKDF2Strategy implements HashingStrategy
{
    private Algorithm algorithm = Algorithm.PBKDF2WithHmacSHA512;

    private int iterations = 64_000;

    private int length = Algorithm.PBKDF2WithHmacSHA512.getBits();

    public static PBKDF2Strategy getInstanceFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            int algorithm = Integer.parseInt(parts[1]);
            long configuration = Long.parseLong(parts[2]);

            int iterations = (int) (configuration >> 32);
            int length = (int) configuration;

            return new PBKDF2Strategy(Algorithm.fromCode(algorithm), iterations, length);
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
    }

    public PBKDF2Strategy()
    {
        //
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
        try
        {
            this.algorithm = Algorithm.valueOf(algorithm);
        }
        catch (IllegalArgumentException iae)
        {
            throw new UnsupportedOperationException("Algorithm `" + algorithm + "` is not recognized.", iae);
        }
    }

    public PBKDF2Strategy(Algorithm algorithm, int iterations, int length)
    {
        this(iterations, length);
        this.algorithm = algorithm;
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
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm.name());
            PBEKeySpec spec = new PBEKeySpec(plain.toCharArray(), salt.getBytes(), iterations, length);
            SecretKey key = secretKeyFactory.generateSecret(spec);
            String params = Long.toString((((long) iterations) << 32) | (length & 0xffffffffL));
            String hash = "$" + algorithm.getCode() + "$" + params + "$" + salt + "$" + Base64.getEncoder()
                    .encodeToString(key.getEncoded());
            return new Hash(this, hash, salt);
        }
        catch (NoSuchAlgorithmException nsae)
        {
            String message = "`" + algorithm + "` is not a valid algorithm";
            throw new UnsupportedOperationException(message, nsae);
        }
        catch (IllegalArgumentException | InvalidKeySpecException e)
        {
            String message = "Invalid specification with salt=" + salt + ", #iterations=`" + iterations + "` and length=`" + length + "`";
            throw new BadParametersException(message, e);
        }
    }

    @Override
    public boolean check(String password, String hashed)
    {
        String salt = getSaltFromHash(hashed);

        Hash internalHas = hash(password, salt);

        return slowEquals(internalHas.getResult().getBytes(), hashed.getBytes());
    }

    private String getSaltFromHash(String hashed)
    {
        String[] parts = hashed.split("\\$");
        if (parts.length == 5)
        {
            return parts[3];
        }
        throw new BadParametersException("`" + hashed + "` is not a valid hash");
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

    public PBKDF2Strategy formattedAs(String format)
    {

        return this;
    }

    public enum Algorithm
    {
        PBKDF2WithHmacSHA1(160, 1), //
        PBKDF2WithHmacSHA224(224, 2), //
        PBKDF2WithHmacSHA256(256, 3), //
        PBKDF2WithHmacSHA384(384, 4), //
        PBKDF2WithHmacSHA512(512, 5);

        private int bits;

        private int code;

        Algorithm(int bits, int code)
        {
            this.bits = bits;
            this.code = code;
        }

        public int getBits()
        {
            return bits;
        }

        public int getCode()
        {
            return code;
        }

        public static Algorithm fromCode(int code)
        {
            for (Algorithm alg : values())
            {
                if (alg.getCode() == code)
                {
                    return alg;
                }
            }
            return null;
        }
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        PBKDF2Strategy otherStrategy = (PBKDF2Strategy) obj;
        return this.algorithm.equals(otherStrategy.algorithm) //
                && this.iterations == otherStrategy.iterations //
                && this.length == otherStrategy.length;
    }

    @Override
    public String toString()
    {
        return getClass().getName() +  Arrays.toString(new int[]{algorithm.getCode(), iterations, length});
    }

    @Override
    public int hashCode()
    {
        return toString().hashCode();
    }
}
