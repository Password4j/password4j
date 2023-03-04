package com.password4j;

import org.junit.Test;

public class EntropyBasedPasswordGeneratorTest
{

    @Test
    public void test()
    {
        EntropyBasedPasswordGenerator generator = EntropyBasedPasswordGenerator.getInstance(30);

        System.out.println(generator.generate(Symbols.PRINTABLE));

    }

}
