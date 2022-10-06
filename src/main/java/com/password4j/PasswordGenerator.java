package com.password4j;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class PasswordGenerator
{

    public String newHOTP(String key, long counter)
    {
        return newHOTP(key.getBytes(StandardCharsets.UTF_8), counter);
    }

    public String newHOTP(byte[] key, long counter)
    {
        HOTPGenerator hotpGenerator = AlgorithmFinder.getHOTPGeneratorInstance();
        return hotpGenerator.generate(key, counter);
    }

    public String newTOTP(byte[] key, Instant instant)
    {
        TOTPGenerator totpGenerator = AlgorithmFinder.getTOTPGeneratorInstance();
        return totpGenerator.generate(key, instant);
    }








}
