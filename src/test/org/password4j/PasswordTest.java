package org.password4j;

import org.junit.Test;


public class PasswordTest
{

    @Test
    public void test()
    {
        Hash hash = Password.from("password").withSalt("").hashWith(new PBKDF2Strategy());
        System.out.println(hash.getResult());
    }
}
