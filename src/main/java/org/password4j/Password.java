package org.password4j;

import org.apache.commons.lang3.StringUtils;


public class Password
{

    private String plain;

    private String salt;

    private String pepper;

    private Password()
    {

    }

    private Password(String plain)
    {
        this();
        this.plain = plain;
    }

    public static Password from(String plain)
    {
        if (plain == null)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return new Password(plain);
    }

    public Password withSalt(String salt)
    {
        this.salt = salt;
        return this;
    }

    public Password withRandomSalt()
    {
        this.salt = new String(SaltGenerator.generate());
        return this;
    }

    public Password withRandomSalt(int length)
    {
        if(length <= 0)
        {
            throw new BadParametersException("Salt cannot have a non-positive length");
        }
        else
        {
            this.salt = new String(SaltGenerator.generate(length));
        }

        return this;
    }

    public Password withPepper(String pepper)
    {
        this.pepper = pepper;
        return this;
    }



    public Hash hashWith(HashingStrategy hashingStrategy)
    {
        String peppered = plain;
        if (StringUtils.isEmpty(this.pepper))
        {
            peppered = this.pepper + peppered;
        }

        if (StringUtils.isEmpty(this.salt))
        {
            return hashingStrategy.hash(peppered);
        }
        else
        {
            return hashingStrategy.hash(peppered, salt);
        }

    }

}
