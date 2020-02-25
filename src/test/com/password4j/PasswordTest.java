package com.password4j;

import org.junit.Test;


public class PasswordTest
{

    @Test
    public void test()
    {
        Hash hash = Password.hash("fabiana").withPBKDF2();


        boolean b = hash.check("java");


        System.out.println(hash);
        System.out.println(b);

    }
}
