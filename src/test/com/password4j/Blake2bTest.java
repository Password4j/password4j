package com.password4j;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Base64;

import org.junit.Test;


public class Blake2bTest
{


    @Test
    public void test1()
    {
        Blake2b instance = new Blake2b();
        instance.update("IamUsingBlake2b###".getBytes());

        byte[] out = new byte[64];
        instance.doFinal(out, 0);

        assertEquals("5fc5a199294099e98280dac6047523aa123ba29e6995618339c9590e4dca983dea2529ad85afbac5613c495b3fb50bf2d5919cb3f51f6a9dba78a33f9d278f6f", Utils.toHex(out));
    }


}

