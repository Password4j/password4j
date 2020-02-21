package org.password4j;

/**
 * This interface is intended as an incapsulation
 * of a particular cryptographic hash function.
 */
public interface HashingStrategy
{
    
    Hash hash(char[] plain);

    Hash hash(char[] plain, byte[] salt);

    boolean check(char[] plain, byte[] hashed);

    boolean check(char[] plain, byte[] hashed, byte[] salt);

}
