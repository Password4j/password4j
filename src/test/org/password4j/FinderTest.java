package org.password4j;

import org.junit.Test;


public class FinderTest
{
    @Test
    public void test()
    {
        for(String s : AlgorithmFinder.getPBKDF2Variants())
        {
            System.out.println(s);
        }
    }
}
