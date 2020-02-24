package org.password4j;

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

}
