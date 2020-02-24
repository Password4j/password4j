package com.password4j;

/**
 * This interface is intended as an incapsulation
 * of a particular cryptographic hash function.
 */
public interface HashingStrategy
{
    
    Hash hash(String plain);

    Hash hash(String plain,String salt);

    boolean check(String plain, String hashed);
}
