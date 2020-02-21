package org.password4j.encryption;

import org.mindrot.jbcrypt.BCrypt;
import org.password4j.AlgorithmFinder;


public class BCryptStrategy implements EncryptionStrategy
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
    public Encryption encrypt(char[] plain)
    {
        String salt = BCrypt.gensalt(logRounds, AlgorithmFinder.getSecureRandom());
        return encrypt(plain, salt.getBytes());
    }

    @Override
    public Encryption encrypt(char[] plain, byte[] salt)
    {
        return internalEncrypt(new String(plain), new String(salt));
    }

    private Encryption internalEncrypt(String plain, String salt)
    {
        String hash = BCrypt.hashpw(plain, salt);
        return new Encryption(Encryption.Status.OK, hash.getBytes(), salt.getBytes());
    }

}
