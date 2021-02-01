package com.password4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;


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

        public TestCase(String plainTextPassword, String salt, int memory, int iterations, int outLength, int parallelism,
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
        }
    }

    private static final List<TestCase> CASES = Arrays.asList(
            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 10, 3, 32, 1,
                    Argon2.D, "$argon2d$v=19$m=1024,t=3,p=1$a1hYRFVFUUhMdzF5dk43$GvtgSr24rB/U/idt+1Xq2tn0DIav/H2W0BybTLZijZY"),

            new TestCase("f6c4db4a54e2a370627aff3db617", "kXXDUEQHLw1yvN7", 10, 3, 32, 3,
                    Argon2.D, "$argon2d$v=19$m=1024,t=3,p=3$a1hYRFVFUUhMdzF5dk43$+2ZPk1DYKqBDxWooR+zPhLCJNCy5gfeDEkh8MaQXf4I"),

            new TestCase("securePassowrd!!!", "mySalt02", 12, 50, 512, 4,
                    Argon2.D, "$argon2d$v=19$m=4096,t=50,p=4$bXlTYWx0MDI$Prd8OUtkdPadnP3MYv1w0DHnUHV6A0sn4tA55nbui1uxKP9AjaD/1qk0OpNkZKObpXJ9slLlb3I8mgYehtbeAGh5uPiVvpfZChfJjbwmDJd3t0d59vhU2+vGO+t/l2t71lPLHKtTwMPmjxybF6QcfCDcOCUW4JBx+RxFj3aCeM7U64aaRphYCRZhNQmidFzydgssU5nlD/EXWz1LaxPUMs+p6qFuvWLyjvyCQo59nJDk9FGtcsL7CJRGvjx7yiggv95fWNg0iTsh3SgicR5OQWfUbUIJtPrdyVuu4QLlUIUhxotjG3SuEcBhuH0Q1jN2PKO/AOP0/2JsLH79wItdPa+w0SzXotNTMFTXhs/aLpzwRtnK2qRvw4BzSTR8Rief1MimG9QxbkGk9sMbmPT5c7ZsxllWLTYy1kwt9ymDBrS34zmL6pn5vK1QOi/VgMMVws+LiXa31+CHdfeR5AtbV0RxskcWDWqNb9//MXXRhlMpMMoFHddyYeHvTSxrHnPAcfur3Dk4K2KAh1q5UEuHGKAfT12l1XhTqNobBhr5W0TbiPW3S/oxIkeee9J2iD0iNks44Cy9vbWwtS9G+z+D+FyYIm/aPBVKxeh8ZbccjAXUC98dxdEKVZ/T7uARuBmVB1Wo6TPkM7j1u+qANu705lrNBagkli+O5TYOJEaWOi4")
    );


    @Test
    public void test()
    {
        for(TestCase test : CASES)
        {
            Argon2Function f = new Argon2Function(test.type, test.iterations, test.memory, test.parallelism, test.outLength);
            assertEquals(test.expected, f.hash(test.plainTextPassword, test.salt).getResult());
        }
    }



}
