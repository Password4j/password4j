package com.password4j;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.Test;


public class Argon2FunctionTest
{

    private static final Charset CHARSET = StandardCharsets.UTF_8;

    @Test
    public void testInitialize()
    {

        Argon2Function function = new Argon2Function(Argon2.I, 3, 2, 1, 32);
        function.hash("password", "saltsalt");



    }


}
