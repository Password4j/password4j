package org.password4j;

import java.util.Arrays;
import java.util.function.Function;

import org.mindrot.jbcrypt.BCrypt;


public class Hash
{
    private static final byte[] EMPTY = new byte[0];

    private byte[] result = EMPTY;

    private byte[] salt = EMPTY;

    private Function<byte[], String> f = (String::new);

    private HashingStrategy hashingStrategy;

    private Hash()
    {
        //
    }

    public Hash(HashingStrategy hashingStrategy, byte[] salt)
    {
        this.hashingStrategy = hashingStrategy;
        this.salt = salt;
    }

    public Hash(HashingStrategy hashingStrategy, byte[] result, byte[] salt)
    {
        this(hashingStrategy, salt);
        this.result = result;
    }

    public byte[] getResult()
    {
        return result;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public String resultAsString()
    {
        return f.apply(result);
    }

    public Hash readResultWith(Function<byte[], String> f)
    {
        this.f = f;
        return this;
    }

    @Override
    public String toString()
    {
        return hashingStrategy.getClass().getSimpleName() + "[" + Arrays.toString(salt) + " - " + resultAsString() + "]";
    }

    public boolean check(String hashed)
    {
        if (hashed == null)
        {
            return false;
        }

        return this.hashingStrategy.check(hashed.toCharArray(), this.getResult(), this.salt);
    }



}
