package com.password4j;

import org.apache.commons.lang3.RandomStringUtils;


public class PepperGenerator
{

    public static String generate(int length)
    {
        return RandomStringUtils.random(length, 32, 126, false, false, null, AlgorithmFinder.getSecureRandom());
    }

    public static String generate()
    {
        return generate(24);
    }

    public static String get()
    {
        return PropertyReader.readString("global.pepper", null);
    }

    public static String get(String context)
    {
        if (context == null)
        {
            return get();
        }
        return PropertyReader.readString(context + ".pepper", null);
    }

}
