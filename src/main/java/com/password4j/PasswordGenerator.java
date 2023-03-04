package com.password4j;

import java.time.Instant;

public class PasswordGenerator
{

    public String newHOTP(CharSequence key, long counter)
    {
        return newHOTP(Utils.fromCharSequenceToBytes(key), counter);
    }

    public String newHOTP(byte[] key, long counter)
    {
        HOTPGenerator hotpGenerator = AlgorithmFinder.getHOTPGeneratorInstance();
        return hotpGenerator.generate(key, counter);
    }

    public String newTOTP(CharSequence key, Instant instant)
    {
        return newTOTP(Utils.fromCharSequenceToBytes(key), instant);
    }

    public String newTOTP(byte[] key, Instant instant)
    {
        TOTPGenerator totpGenerator = AlgorithmFinder.getTOTPGeneratorInstance();
        return totpGenerator.generate(key, instant);
    }










}
