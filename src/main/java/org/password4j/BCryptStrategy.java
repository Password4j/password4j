package org.password4j;

import org.mindrot.jbcrypt.BCrypt;


public class BCryptStrategy implements HashingStrategy
{
    private int logRounds = 10;

    public BCryptStrategy()
    {

    }

    public BCryptStrategy(int logRounds)
    {
        this();
        this.logRounds = logRounds;
    }

    @Override
    public Hash hash(char[] plain)
    {
        String salt = BCrypt.gensalt(logRounds, AlgorithmFinder.getSecureRandom());
        return hash(plain, salt.getBytes());
    }

    @Override
    public Hash hash(char[] plain, byte[] salt)
    {
        return hash(new String(plain), new String(salt));
    }

    @Override
    public boolean check(char[] password, byte[] hashed)
    {
        return BCrypt.checkpw(new String(password), new String(hashed));
    }

    @Override
    public boolean check(char[] password, byte[] hashed, byte[] salt)
    {
        return false;
    }

    private Hash hash(String plain, String salt)
    {
        try
        {
            String hash = BCrypt.hashpw(plain, salt);
            return new Hash(this, hash.getBytes(), salt.getBytes());
        }
        catch (IllegalArgumentException iae)
        {
            String message = "Invalid specification with salt=" + salt + " and #rounds=`" + logRounds + "`";
            throw new BadParametersException(message, iae);
        }

    }

}
