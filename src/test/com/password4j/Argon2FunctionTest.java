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

import com.password4j.types.Argon2;
import com.password4j.types.Bcrypt;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class Argon2FunctionTest
{


    static class TestCase
    {
        String plainTextPassword;
        String salt;
        int memory;
        int iterations;
        int outLength;
        int parallelism;
        Argon2 type;
        String expected;
        int version;

        TestCase(String plainTextPassword, String salt, int memory, int iterations, int outLength, int parallelism,
                 Argon2 type, String expected)
        {
            this.plainTextPassword = plainTextPassword;
            this.salt = salt;
            this.memory = memory;
            this.iterations = iterations;
            this.outLength = outLength;
            this.parallelism = parallelism;
            this.type = type;
            this.expected = expected;
            this.version = Argon2Function.ARGON2_VERSION_13;
        }

        TestCase(String plainTextPassword, String salt, int memory, int iterations, int outLength, int parallelism, int version,
                 Argon2 type, String expected)
        {
            this(plainTextPassword, salt, memory, iterations, outLength, parallelism, type, expected);
            this.version = version;
        }
    }

    private static final List<TestCase> CASES = Arrays.asList(

            // STANDARD

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 1,
                    Argon2.D, "$argon2d$v=19$m=1024,t=3,p=1$a1hYRFVFUUhMdzF5dk43$GvtgSr24rB/U/idt+1Xq2tn0DIav/H2W0BybTLZijZY"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 3,
                    Argon2.D, "$argon2d$v=19$m=1024,t=3,p=3$a1hYRFVFUUhMdzF5dk43$+2ZPk1DYKqBDxWooR+zPhLCJNCy5gfeDEkh8MaQXf4I"),

            new TestCase("securePassowrd!!!", "mySalt02", 4096, 50, 512, 4,
                    Argon2.D, "$argon2d$v=19$m=4096,t=50,p=4$bXlTYWx0MDI$Prd8OUtkdPadnP3MYv1w0DHnUHV6A0sn4tA55nbui1uxKP9AjaD/1qk0OpNkZKObpXJ9slLlb3I8mgYehtbeAGh5uPiVvpfZChfJjbwmDJd3t0d59vhU2+vGO+t/l2t71lPLHKtTwMPmjxybF6QcfCDcOCUW4JBx+RxFj3aCeM7U64aaRphYCRZhNQmidFzydgssU5nlD/EXWz1LaxPUMs+p6qFuvWLyjvyCQo59nJDk9FGtcsL7CJRGvjx7yiggv95fWNg0iTsh3SgicR5OQWfUbUIJtPrdyVuu4QLlUIUhxotjG3SuEcBhuH0Q1jN2PKO/AOP0/2JsLH79wItdPa+w0SzXotNTMFTXhs/aLpzwRtnK2qRvw4BzSTR8Rief1MimG9QxbkGk9sMbmPT5c7ZsxllWLTYy1kwt9ymDBrS34zmL6pn5vK1QOi/VgMMVws+LiXa31+CHdfeR5AtbV0RxskcWDWqNb9//MXXRhlMpMMoFHddyYeHvTSxrHnPAcfur3Dk4K2KAh1q5UEuHGKAfT12l1XhTqNobBhr5W0TbiPW3S/oxIkeee9J2iD0iNks44Cy9vbWwtS9G+z+D+FyYIm/aPBVKxeh8ZbccjAXUC98dxdEKVZ/T7uARuBmVB1Wo6TPkM7j1u+qANu705lrNBagkli+O5TYOJEaWOi4"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 1,
                    Argon2.I, "$argon2i$v=19$m=1024,t=3,p=1$a1hYRFVFUUhMdzF5dk43$cJfBg8Ki319tkv9pVuy3FcqpQGj3uDLlhqkw3EILJ9c"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 3,
                    Argon2.I, "$argon2i$v=19$m=1024,t=3,p=3$a1hYRFVFUUhMdzF5dk43$ZMPK1QfA5x1RQWMS80rzq6SE2OAs+Bdd+9ktPe7uZUo"),

            new TestCase("securePassowrd!!!", "mySalt02", 4096, 50, 512, 4,
                    Argon2.I, "$argon2i$v=19$m=4096,t=50,p=4$bXlTYWx0MDI$voZUGPEULMj+5jSK3eJiV6WXW/NLWnUNgPprUnPX1K0/JkQSkNMcPXZg07CJzNgu4d91JdHS3z4dRHlYTBK8CDTChbMJUeF9kVo4tUBtrVKaLEaZOgu4/EvuBlRBZmp5R24OkglBpGT3BbBSLx/WOjlJG/SY1WElbmbeJMVBDj3cGRMlf6uYwuumze6FSDnHVm1zV6PGMF+cOt9JyDhRrzJLUkbd8yT/Z/LMy0CKbnE8FLdW0zGqNPAV6t+GexPUWrvi0ilC5B+kk6UZA5UUKs8/D5CO7k4i6NYAoAUXOk572pGkg2qftsxl8+al4ffen2FTQQ3r4TD2vUW3VRW5W7UmT4fiIVc1XFcTIyDG+J3uFovSyWlSnGd2M1hkO2dbxGnvOY96SCL5BGBpXxKifVJclC91LHKYOWg2eVZQHZZ2jFmS5YEuzH+pFisWyncQ7VodDFiTlk/zZj5TfV6jPQnubPcO2iFkaJrgUgCotFA2l6Ddl9IUdpzVUQHmaEXceGawcZ8vN8f64rO8euTp2fAGjtBf7p6sQIVOYdYLazKhK+x2sMNur+8oJybWrQtZNu+GcN3y0cMMrPyKjnb5gwmkOS/3eYBHqFT7hgs1C6eBgrnyxMuqZbj7mb5ABiNocYnlKiFbhtMQbEiyFwroNvWqZ74yzpQScBlh4yhS1qs"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 1,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=1$a1hYRFVFUUhMdzF5dk43$oZQjFpZE3edaKLPT88nwAqxlLLv3JQA3Et5i+0u7hso"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 1024, 3, 32, 3,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=3$a1hYRFVFUUhMdzF5dk43$+pbPYkP4PTHdGhl4syeyZihZHKP74mbz8PH112/pw+k"),

            new TestCase("securePassowrd!!!", "mySalt02", 4096, 50, 512, 4,
                    Argon2.ID, "$argon2id$v=19$m=4096,t=50,p=4$bXlTYWx0MDI$eI9VrXKlaAxuSmWHmEFlihNHOlWmpSRmxlKbpw33NDIgbTjS7d6AHq7RbmQ+x2A2ENN8TUygvNvYymV6ufQqiVx6QORXv2gfIyI2mPzygP3ZdCKG0r2Sx4RJa8DClkV9/SMFs4fcSTUkI3IVn4M4lguOe4oEq6ig0M9P5VzsRvgCyfCMLIBGUlQqMDxfyIyk4RA3SNvwwqvaZPDSlid+0TzXiLv5IoQkpeW3W2moehkBL9fs/PwIQZZlJVVQXGRZ40U26ny8d0HLkaIch+MKX/sT7yPaicGEfRkpdec4biI+V8BgzZRFYg7hRxM5FJTSsvMs+xomuEEKDlXWjD4LlCPtRNWF5nZ/yagUSXU7rFi3E2zM57gdqltZNDmqXGDdIH/Ev5Rw5qGm0DUxOAvTCgMy953GVLa6fuTX86cEpWDNMGVSzSSS+8aWt4d5QNbLhh5nwkEw/2eer2AyZiRI3W+JYoXaY0H4oL6xOxwWOqS2KC661aZVCtu5m8mvAtCkC4Hq9DvSBTqdZrsQXhh7salmooXNKpUeM/05ifAWf2BBRSK5HNxXzkC2iB2et4yeA5/yOqQu89e7qGfp7EU9jAtwqy4VvVLdp1CYcTuMnUy7nGAnDDOYX1+jTyY4NJ6eRxQVfjDdIqIPB95qhyjsZ8jjZIqWxaoxhMARfmi3rl4"),


            // MINIMAL

            new TestCase("mini", "12345678", 8, 1, 4, 1,
                    Argon2.D, "$argon2d$v=19$m=8,t=1,p=1$MTIzNDU2Nzg$zdVOjw"),

            new TestCase("mini", "12345678", 8, 1, 4, 1,
                    Argon2.I, "$argon2i$v=19$m=8,t=1,p=1$MTIzNDU2Nzg$Gn9A4g"),

            new TestCase("mini", "12345678", 8, 1, 4, 1,
                    Argon2.ID, "$argon2id$v=19$m=8,t=1,p=1$MTIzNDU2Nzg$zJ0Sag"),


            // REPETITIVE
            new TestCase("first!", "11111111", 1024, 3, 32, 12,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=12$MTExMTExMTE$0PUE8wVEaK0qdjms3b4pTZOs0+00S/+9j28WZ3gMUno"),

            new TestCase("second?", "22222222", 1024, 3, 32, 12,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=12$MjIyMjIyMjI$f38E3C9DdqJ5dq5pCe27FXMQiTAlx47ulfTPKDf+feg"),

            new TestCase("third#", "33333333", 1024, 3, 32, 12,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=12$MzMzMzMzMzM$DXUE5N4lm4plldg9nGMq+tYsbGhko8HWpPaADujpgFQ"),

            new TestCase("fourth@", "44444444", 1024, 3, 32, 12,
                    Argon2.ID, "$argon2id$v=19$m=1024,t=3,p=12$NDQ0NDQ0NDQ$HEoprKMypoVVGYR71EKw66gUFTndNs/p1joWXmeUVvk"),


            // PARAM
            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 512, 13, 17, 3,
                    Argon2.ID, "$argon2id$v=19$m=512,t=13,p=3$a1hYRFVFUUhMdzF5dk43$GH89G/RebgaZwv4pyeWG7lU"),

            new TestCase("mini", "12345678", 32, 10, 32, 4, 0x10,
                    Argon2.I, "$argon2i$v=16$m=32,t=10,p=4$MTIzNDU2Nzg$Tu4w/edteuxnqMFDkR2QBgcDc3rjIzJeEo8C44nDiCM")

    );


    @Test
    public void test()
    {
        for (TestCase test : CASES)
        {
            Argon2Function f = getFunction(test.memory, test.iterations, test.parallelism, test.outLength, test.type, test.version);
            assertEquals(test.expected, f.hash(test.plainTextPassword, test.salt).getResult());
        }
    }


    @Test
    public void parallelTest() throws InterruptedException, ExecutionException
    {

        ExecutorService executors = Executors.newCachedThreadPool();
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (final TestCase test : CASES)
        {
            Callable<Boolean> c = () -> test.expected.equals(getFunction(test.memory, test.iterations, test.parallelism, test.outLength, test.type, test.version).hash(test.plainTextPassword, test.salt).getResult());
            tasks.add(c);
        }
        List<Future<Boolean>> results = executors.invokeAll(tasks);

        for (Future<Boolean> future : results)
        {
            assertTrue(future.get());
        }

    }

    @Test(expected = BadParametersException.class)
    public void badHash()
    {
        // GIVEN
        String invalidHash = "$argon2d$v=19Sm=1024,t=3,p=1$a1hYRFVFUUhMdzF5dk43$GvtgSr24rB/U/idt+1Xq2tn0DIav/H2W0BybTLZijZY";

        // WHEN
        Argon2Function.getInstanceFromHash(invalidHash);

        // TEST
    }

    private Argon2Function getFunction(int memory, int iterations, int parallelism, int outLength, Argon2 type,int version)
    {
        if (version == Argon2Function.ARGON2_VERSION_13)
        {
            return Argon2Function.getInstance(memory, iterations, parallelism, outLength, type);
        }
        else
        {
            return Argon2Function.getInstance(memory, iterations, parallelism, outLength, type, version);
        }
    }


    @Test
    public void testEquality()
    {
        // GIVEN
        int m = 1;
        int i = 2;
        int p = 3;
        int l = 4;
        Argon2 t = Argon2.D;
        int v = 0x13;
        Argon2Function argon2 = Argon2Function.getInstance(m, i, p, l, t, v);

        // THEN
        boolean eqNull = argon2.equals(null);
        boolean eqClass = argon2.equals(new BcryptFunction(Bcrypt.A, 10));
        boolean sameInst = argon2.equals(Argon2Function.getInstance(m, i, p, l, t, v));
        boolean sameInst2 = argon2.equals(new Argon2Function(m, i, p, l, t, v));
        String toString = argon2.toString();
        int hashCode = argon2.hashCode();
        boolean notSameInst1 = argon2.equals(new Argon2Function(m+1, i, p, l, t, v));
        boolean notSameInst2 = argon2.equals(new Argon2Function(m, i+1, p, l, t, v));
        boolean notSameInst3 = argon2.equals(new Argon2Function(m, i, p+1, l, t, v));
        boolean notSameInst4 = argon2.equals(new Argon2Function(m, i, p, l+1, t, v));
        boolean notSameInst5 = argon2.equals(new Argon2Function(m, i, p, l, Argon2.ID, v));
        boolean notSameInst6 = argon2.equals(new Argon2Function(m, i, p, l, t, v+1));

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertTrue(sameInst);
        Assert.assertTrue(sameInst2);
        Assert.assertNotEquals(toString, new Argon2Function(m, i+1, p, l, t, v).toString());
        Assert.assertNotEquals(hashCode, new Argon2Function(m, i, p, l, t, v+1).hashCode());
        Assert.assertFalse(notSameInst1);
        Assert.assertFalse(notSameInst2);
        Assert.assertFalse(notSameInst3);
        Assert.assertFalse(notSameInst4);
        Assert.assertFalse(notSameInst5);
        Assert.assertFalse(notSameInst6);
    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        int memory = 3;
        int iterations = 5;
        int parallelism = 7;
        int outputLength = 11;
        Argon2 variant = Argon2.D;
        int version = 13;

        // WHEN
        Argon2Function argon2Function = Argon2Function.getInstance(memory, iterations, parallelism, outputLength, variant, version);

        // THEN
        Assert.assertEquals(memory, argon2Function.getMemory());
        Assert.assertEquals(iterations, argon2Function.getIterations());
        Assert.assertEquals(parallelism, argon2Function.getParallelism());
        Assert.assertEquals(outputLength, argon2Function.getOutputLength());
        Assert.assertEquals(variant, argon2Function.getVariant());
        Assert.assertEquals(version, argon2Function.getVersion());

        Assert.assertEquals("Argon2Function[m=3, i=5, p=7, l=11, t=D, v=13]", argon2Function.toString());
    }

    @Test
    public void testOWASP()
    {
        // GIVEN
        Properties oldProps = PropertyReader.properties;
        PropertyReader.properties = null;

        // WHEN
        Argon2Function argon2 = AlgorithmFinder.getArgon2Instance();

        // THEN
        assertEquals(15360, argon2.getMemory());
        assertEquals(2, argon2.getIterations());
        assertEquals(1, argon2.getParallelism());
        assertEquals(32, argon2.getOutputLength());
        assertEquals(Argon2.ID, argon2.getVariant());
        assertEquals(19, argon2.getVersion());

        PropertyReader.properties = oldProps;
    }

    @Test
    public void testWithGeneratedSalt()
    {
        for (TestCase test : CASES)
        {
            Argon2Function f = getFunction(test.memory, test.iterations, test.parallelism, test.outLength, test.type, test.version);
            Hash hash = Password.hash(test.plainTextPassword).addRandomSalt().with(f);
            assertTrue(Password.check(test.plainTextPassword, hash));
        }
    }

    @Test
    public void testWithGeneratedSaltAndSetLenght()
    {
        for (TestCase test : CASES)
        {
            Argon2Function f = getFunction(test.memory, test.iterations, test.parallelism, test.outLength, test.type, test.version);
            Hash hash = Password.hash(test.plainTextPassword).addRandomSalt(128).with(f);
            assertTrue(Password.check(test.plainTextPassword, hash));
        }
    }




}
