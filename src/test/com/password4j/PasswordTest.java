package com.password4j;

import org.junit.Test;


public class PasswordTest
{

    @Test
    public void test()
    {
        Hash hash = Password.hash("my secret password").addSalt("qb").with(new SCryptStrategy());

        System.out.println(hash);
    }
}
