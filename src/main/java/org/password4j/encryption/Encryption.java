package org.password4j.encryption;

public class Encryption
{

    private byte[] result;

    private byte[] salt;

    private Status status;

    enum Status
    {
        OK, UNSUPPORTED, BAD_PARAMS
    }

    public Encryption(Status status, byte[] result, byte[] salt)
    {
        this.status = status;
        this.result = result;
        this.salt = salt;
    }

    public byte[] getResult()
    {
        return result;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public Status getStatus()
    {
        return status;
    }
}
