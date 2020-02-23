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
    public Hash hash(String plain)
    {
        String salt = BCrypt.gensalt(logRounds, AlgorithmFinder.getSecureRandom());
        return hash(plain, salt);
    }

    @Override
    public Hash hash(String plain, String salt)
    {
        return internalHash(plain, salt);
    }

    @Override
    public boolean check(String password, String hashed)
    {
        return BCrypt.checkpw(password, hashed);
    }


    private Hash internalHash(String plain, String salt)
    {
        try
        {
            String hash = BCrypt.hashpw(plain, salt);
            return new Hash(this, hash, salt);
        }
        catch (IllegalArgumentException iae)
        {
            String message = "Invalid specification with salt=" + salt + " and #rounds=`" + logRounds + "`";
            throw new BadParametersException(message, iae);
        }

    }

}
