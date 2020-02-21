package org.password4j.encryption;

/**
 * This interface is intended as an incapsulation
 * of a particular cryptographic hash function.
 */
public interface EncryptionStrategy
{
    
    Encryption encrypt(char[] plain);

    Encryption encrypt(char[] plain, byte[] salt);

}
