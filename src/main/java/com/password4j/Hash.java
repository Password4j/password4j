package com.password4j;

import java.util.Objects;

import org.apache.commons.lang3.StringUtils;


/**
 * This class contains all the information computed after
 * calculating a cryptographic hash.
 * <p>
 * The same {@link HashingStrategy} used to generate the hash
 * is used to verify the plain password; in addition <i>cryptographic
 * seasoning</i> such as salt and pepper are stored in this object.
 * <p>
 *
 * @author David Bertoldi
 * @since 1.0.0
 */
public class Hash
{
    /**
     * Represents the full output of a cryptographic hashing function.
     */
    private String result = StringUtils.EMPTY;

    /**
     * Represents the salt: random data that is used as an additional input
     * to a cryptographic hashing function.
     */
    private String salt = StringUtils.EMPTY;

    /**
     * Represents the pepper: a secret added to the input password
     * prior to being hashed with a cryptographic hash function
     */
    private String pepper;

    /**
     * Represents the hashing function used to generate this object.
     */
    private HashingStrategy hashingStrategy;

    private Hash()
    {
        //
    }

    /**
     * Constructs an {@link Hash} containing the basic information
     * used and produced by the computational process of hashing a password.
     * Other information, like <i>pepper</i> can be added with
     * {@link #setPepper(String)}.
     * <p>
     * This constructor populates the object's attributes.
     *
     * @param hashingStrategy the cryptographic algorithm used to produce the hash.
     * @param result          the result of the computation of the hash. Notice that the format vary depending on the algorithm.
     * @param salt            the salt used for the computation.
     * @since 1.0.0
     */
    public Hash(HashingStrategy hashingStrategy, String result, String salt)
    {
        this.hashingStrategy = hashingStrategy;
        this.salt = salt;
        this.result = result;
    }

    /**
     * Retrieves the hash computed by the hashing function.
     *
     * @return the hash.
     * @since 1.0.0
     */
    public String getResult()
    {
        return result;
    }

    /**
     * Retrieves the salt used by the hashing function.
     *
     * @return the salt.
     * @since 1.0.0
     */
    public String getSalt()
    {
        return salt;
    }

    /**
     * Retrieved the pepper used together with the password in the hashing function.
     *
     * @return the pepper.
     * @since 1.0.0
     */
    public String getPepper()
    {
        return pepper;
    }

    /**
     * Stores the pepper used together with the password in the hashing function.
     *
     * @param pepper the pepper used.
     * @since 1.0.0
     */
    void setPepper(String pepper)
    {
        this.pepper = pepper;
    }

    /**
     * Uses the {@link HashingStrategy} used to calculate this {@link Hash}.
     * Il the password is null, this returns false; otherwise {@link HashingStrategy#check(String, String)} is invoked.
     *
     * @param plain the original password.
     * @return true if the check passes, false otherwise.
     * @since 1.0.0
     */
    public boolean check(String plain)
    {
        if (plain == null)
        {
            return false;
        }

        return this.hashingStrategy.check(plain, this.getResult());
    }

    @Override
    public String toString()
    {
        return hashingStrategy.getClass()
                .getSimpleName() + "[salt=" + getSalt() + ", pepper=" + getPepper() + ", hash=" + getResult() + "]";
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        Hash otherHash = (Hash) obj;
        return this.result.equals(otherHash.result) && this.salt.equals(otherHash.salt);
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(result, salt, pepper, hashingStrategy);
    }
}
