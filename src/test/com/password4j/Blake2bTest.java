/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.password4j;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class Blake2bTest
{

    static class TestCase
    {
        String message;
        int length;
        String expected;

        public TestCase(String message, int length, String expected)
        {
            this.message = message;
            this.length = length;
            this.expected = expected;
        }
    }

    private static final List<Blake2bTest.TestCase> CASES = Arrays.asList(
        new TestCase("IamUsingBlake2b###", 512/8, "5fc5a199294099e98280dac6047523aa123ba29e6995618339c9590e4dca983dea2529ad85afbac5613c495b3fb50bf2d5919cb3f51f6a9dba78a33f9d278f6f"),
            new TestCase(null, 512/8, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
            new TestCase(null, 384/8, "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"),
            new TestCase(null, 256/8, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"),
            new TestCase(null, 224/8, "836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07"),

            new TestCase("0", 384/8, "c62e79958b2e7796d4b6afaba57b3a929a5c38125f56703cae90a952a96a6ef2a2d42376fe7183222779e3790fc95a22"),

            new TestCase("!$%^&*()_+@~{}", 512/8, "a7128f0b9a745d7073be967e2dc4ceb5e326a998ca45c451835c1c4eecd499dea1c1e04e15e890b2ac32675baea270785dd12d591646bc4df7c545b31041ed22")
    );


    @Test
    public void test()
    {
        for (TestCase test : CASES)
        {
            Blake2b instance = new Blake2b(test.length);
            instance.update(test.message == null ? null : test.message.getBytes(Utils.DEFAULT_CHARSET));
            byte[] out = new byte[test.length];
            instance.doFinal(out, 0);
            assertEquals(test.expected, Utils.toHex(out));
        }
    }


    @Test
    public void parallelTest() throws InterruptedException, ExecutionException
    {

        ExecutorService executors = Executors.newCachedThreadPool();
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (final TestCase test : CASES)
        {
            Callable<Boolean> c = () -> {
                Blake2b instance = new Blake2b(test.length);
                instance.update(test.message == null ? null : test.message.getBytes(Utils.DEFAULT_CHARSET));
                byte[] out = new byte[test.length];
                instance.doFinal(out, 0);
                return test.expected.equals(Utils.toHex(out));
            };
            tasks.add(c);
        }
        List<Future<Boolean>> results = executors.invokeAll(tasks);

        for (Future<Boolean> future : results)
        {
            assertTrue(future.get());
        }

    }

    @Test(expected = BadParametersException.class)
    public void badTest1()
    {
        // GIVEN

        // WHEN
        new Blake2b(0);
    }


    @Test(expected = BadParametersException.class)
    public void badTest2()
    {
        // GIVEN

        // WHEN
        new Blake2b(65);
    }







}

