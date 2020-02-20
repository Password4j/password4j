package org.password4j;

import java.security.SecureRandom;


public class SaltGenerator
{

    public static byte[] generate(int length)
    {
        byte[] salt = new byte[length];
        SecureRandom sr = AlgorithmFinder.getSecureRandom();
        sr.nextBytes(salt);
        return salt;
    }

    public static byte[] generate()
    {
        return generate(64);
    }

}
