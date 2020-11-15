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

import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.*;


public class BCryptFunctionTest
{

    @Test(expected = BadParametersException.class)
    public void testBCryptBadParams()
    {
        // GIVEN
        HashingFunction strategy = new BCryptFunction(BCrypt.Y,-1);
        String password = "password";

        // WHEN
        strategy.hash(password);

        // THEN
    }

    @Test
    public void testBCryptCoherence()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new BCryptFunction(BCrypt.A,10).hash(password);

        // THEN
        Assert.assertTrue(Password.check(password, hash));

    }

    @Test
    public void testBCryptCheckWithFixedConfigurations()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new BCryptFunction(BCrypt.A,12).hash(password);

        // THEN
        Assert.assertTrue(Password.check(password, hash));
    }

    @Test
    public void testBCryptequality()
    {
        // GIVEN
        BCryptFunction strategy1 = new BCryptFunction(BCrypt.A,10);
        BCryptFunction strategy2 = new BCryptFunction(BCrypt.A,10);
        BCryptFunction strategy3 = new BCryptFunction(BCrypt.A,15);
        BCryptFunction strategy4 = new BCryptFunction(BCrypt.A,15);
        BCryptFunction strategy5 = new BCryptFunction(BCrypt.A,8);

        // WHEN
        Map<BCryptFunction, String> map = new HashMap<>();
        map.put(strategy1, strategy1.toString());
        map.put(strategy2, strategy2.toString());
        map.put(strategy3, strategy3.toString());
        map.put(strategy4, strategy4.toString());
        map.put(strategy5, strategy5.toString());

        // THEN
        Assert.assertEquals(3, map.size());
        Assert.assertEquals(strategy1, strategy2);
        Assert.assertEquals(strategy3, strategy4);
    }

    @Test
    public void testLongPassword()
    {
        // GIVEN
        String password1 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor";
        String password2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod 7€Mp0R";
        String salt = "$2a$10$bJ2SJm8Xyp8H9KLeyNE5EO";

        // WHEN
        Hash hash1 = new BCryptFunction(BCrypt.A, 10).hash(password1, salt);
        Hash hash2 = new BCryptFunction(BCrypt.A,10).hash(password2, salt);

        // THEN
        Assert.assertEquals(hash1, hash2);

    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int rounds = 8;
        BCryptFunction bcrypt = new BCryptFunction(BCrypt.A,rounds);

        // THEN
        boolean eqNull = bcrypt.equals(null);
        boolean eqClass = bcrypt.equals(new BCryptFunction(BCrypt.A,10));
        boolean difInst = bcrypt.equals(new BCryptFunction(BCrypt.A,10));
        boolean sameInst = bcrypt.equals(new BCryptFunction(BCrypt.A,rounds));

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertFalse(difInst);
        Assert.assertTrue(sameInst);
    }

    private static class TestObject<T>
    {
        private T password;
        private String salt;
        private String expected;
        private int rounds;

        private TestObject(T password, String salt, String expected, int rounds)
        {
            this.password = password;
            this.salt = salt;
            this.expected = expected;
            this.rounds = rounds;
        }
    }


    private static List<TestObject<String>> testObjectsString;

    @BeforeClass
    public static void setupTestObjects()
    {
        testObjectsString = new ArrayList<>();
        testObjectsString.add(new TestObject<>("", "$2a$06$DCq7YPn5Rq63x1Lad4cll.",
                "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", 6));
        testObjectsString.add(new TestObject<>("", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.",
                "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye", 8));
        testObjectsString.add(new TestObject<>("", "$2a$10$k1wbIrmNyFAPwPVPSVa/ze",
                "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW", 10));
        testObjectsString.add(new TestObject<>("", "$2a$12$k42ZFHFWqBp3vWli.nIn8u",
                "$2a$12$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO", 12));
        testObjectsString.add(new TestObject<>("", "$2b$06$8eVN9RiU8Yki430X.wBvN.",
                "$2b$06$8eVN9RiU8Yki430X.wBvN.LWaqh2962emLVSVXVZIXJvDYLsV0oFu", 6));
        testObjectsString.add(new TestObject<>("", "$2b$06$NlgfNgpIc6GlHciCkMEW8u",
                "$2b$06$NlgfNgpIc6GlHciCkMEW8uKOBsyvAp7QwlHpysOlKdtyEw50WQua2", 6));
        testObjectsString.add(new TestObject<>("", "$2y$06$mFDtkz6UN7B3GZ2qi2hhaO",
                "$2y$06$mFDtkz6UN7B3GZ2qi2hhaO3OFWzNEdcY84ELw6iHCPruuQfSAXBLK", 6));
        testObjectsString.add(new TestObject<>("", "$2y$06$88kSqVttBx.e9iXTPCLa5u",
                "$2y$06$88kSqVttBx.e9iXTPCLa5uFPrVFjfLH4D.KcO6pBiAmvUkvdg0EYy", 6));
        testObjectsString.add(new TestObject<>("a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO",
                "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe", 6));
        testObjectsString.add(new TestObject<>("a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfe",
                "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V.", 8));
        testObjectsString.add(new TestObject<>("a", "$2a$10$k87L/MF28Q673VKh8/cPi.",
                "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u", 10));
        testObjectsString.add(new TestObject<>("a", "$2a$12$8NJH3LsPrANStV6XtBakCe",
                "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS", 12));
        testObjectsString.add(new TestObject<>("a", "$2b$06$ehKGYiS4wt2HAr7KQXS5z.",
                "$2b$06$ehKGYiS4wt2HAr7KQXS5z.OaRjB4jHO7rBHJKlGXbqEH3QVJfO7iO", 6));
        testObjectsString.add(new TestObject<>("a", "$2b$06$PWxFFHA3HiCD46TNOZh30e",
                "$2b$06$PWxFFHA3HiCD46TNOZh30eNto1hg5uM9tHBlI4q/b03SW/gGKUYk6", 6));
        testObjectsString.add(new TestObject<>("a", "$2y$06$LUdD6/aD0e/UbnxVAVbvGu",
                "$2y$06$LUdD6/aD0e/UbnxVAVbvGuUmIoJ3l/OK94ThhadpMWwKC34LrGEey", 6));
        testObjectsString.add(new TestObject<>("a", "$2y$06$eqgY.T2yloESMZxgp76deO",
                "$2y$06$eqgY.T2yloESMZxgp76deOROa7nzXDxbO0k.PJvuClTa.Vu1AuemG", 6));
        testObjectsString.add(new TestObject<>("abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu",
                "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", 6));
        testObjectsString.add(new TestObject<>("abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7O",
                "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm", 8));
        testObjectsString.add(new TestObject<>("abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.",
                "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi", 10));
        testObjectsString.add(new TestObject<>("abc", "$2a$12$EXRkfkdmXn2gzds2SSitu.",
                "$2a$12$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q", 12));
        testObjectsString.add(new TestObject<>("abc", "$2b$06$5FyQoicpbox1xSHFfhhdXu",
                "$2b$06$5FyQoicpbox1xSHFfhhdXuR2oxLpO1rYsQh5RTkI/9.RIjtoF0/ta", 6));
        testObjectsString.add(new TestObject<>("abc", "$2b$06$1kJyuho8MCVP3HHsjnRMkO",
                "$2b$06$1kJyuho8MCVP3HHsjnRMkO1nvCOaKTqLnjG2TX1lyMFbXH/aOkgc.", 6));
        testObjectsString.add(new TestObject<>("abc", "$2y$06$ACfku9dT6.H8VjdKb8nhlu",
                "$2y$06$ACfku9dT6.H8VjdKb8nhluaoBmhJyK7GfoNScEfOfrJffUxoUeCjK", 6));
        testObjectsString.add(new TestObject<>("abc", "$2y$06$9JujYcoWPmifvFA3RUP90e",
                "$2y$06$9JujYcoWPmifvFA3RUP90e5rSEHAb5Ye6iv3.G9ikiHNv5cxjNEse", 6));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu",
                "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC", 6));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhge",
                "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz.", 8));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1u",
                "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq", 10));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2a$12$D4G5f18o7aMMfwasBL7Gpu",
                "$2a$12$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG", 12));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2b$06$O8E89AQPj1zJQA05YvIAU.",
                "$2b$06$O8E89AQPj1zJQA05YvIAU.hMpj25BXri1bupl/Q7CJMlpLwZDNBoO", 6));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2b$06$PDqIWr./o/P3EE/P.Q0A/u",
                "$2b$06$PDqIWr./o/P3EE/P.Q0A/uFg86WL/PXTbaW267TDALEwDylqk00Z.", 6));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2y$06$34MG90ZLah8/ZNr3ltlHCu",
                "$2y$06$34MG90ZLah8/ZNr3ltlHCuz6bachF8/3S5jTuzF1h2qg2cUk11sFW", 6));
        testObjectsString.add(new TestObject<>("abcdefghijklmnopqrstuvwxyz", "$2y$06$AK.hSLfMyw706iEW24i68u",
                "$2y$06$AK.hSLfMyw706iEW24i68uKAc2yorPTrB0cimvjJHEBUrPkOq7VvG", 6));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.",
                "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO", 6));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262hu",
                "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW", 8));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe",
                "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS", 10));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$12$WApznUOJfkEGSmYRfnkrPO",
                "$2a$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC", 12));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$06$FGWA8OlY6RtQhXBXuCJ8Wu",
                "$2b$06$FGWA8OlY6RtQhXBXuCJ8WusVipRI15cWOgJK8MYpBHEkktMfbHRIG", 6));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2b$06$G6aYU7UhUEUDJBdTgq3CRe",
                "$2b$06$G6aYU7UhUEUDJBdTgq3CRekiopCN4O4sNitFXrf5NUscsVZj3a2r6", 6));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2y$06$sYDFHqOcXTjBgOsqC0WCKe",
                "$2y$06$sYDFHqOcXTjBgOsqC0WCKeMd3T1UhHuWQSxncLGtXDLMrcE6vFDti", 6));
        testObjectsString.add(new TestObject<>("~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2y$06$6Xm0gCw4g7ZNDCEp4yTise",
                "$2y$06$6Xm0gCw4g7ZNDCEp4yTisez0kSdpXEl66MvdxGidnmChIe8dFmMnq", 6));


    }

    /**
     * Test method for 'BCrypt.hashpw(String, String)'
     */
    @Test
    public void testHashpw()
    {
        for (TestObject<String> test : testObjectsString)
        {
            Hash hash = BCryptFunction.getInstance(test.rounds).hash(test.password, test.salt);
            Assert.assertEquals(hash.getResult(), test.expected);

            int rounds = BCryptFunction.getInstanceFromHash(test.expected).getLogarithmicRounds();
            Assert.assertEquals(test.rounds, rounds);
        }
    }

    @Test(expected = BadParametersException.class)
    public void testBadFromHash1()
    {
        // GIVEN
        String hash = "$2yS06$6Xm0gCw4g7ZNDCEp4yTisez0kSdpXEl66MvdxGidnmChIe8dFmMnq";

        // WHEN
        BCryptFunction function = BCryptFunction.getInstanceFromHash(hash);

        // THEN
        Assert.assertEquals(6, function.getLogarithmicRounds());
    }


    @Test(expected = BadParametersException.class)
    public void testBadFromHash2()
    {
        // GIVEN
        String hash = "$a$06$6Xm0gCw4g7ZNDCEp4yTisez0kSdpXEl66MvdxGidnmChIe8dFmMnq";

        // WHEN
        BCryptFunction function = BCryptFunction.getInstanceFromHash(hash);

        // THEN
        Assert.assertEquals(6, function.getLogarithmicRounds());
    }

    @Test
    public void testFromHash()
    {
        // GIVEN
        String hash = "$2$06$6Xm0gCw4g7ZNDCEp4yTisez0kSdpXEl66MvdxGidnmChIe8dFmMnq";

        // WHEN
        BCryptFunction function = BCryptFunction.getInstanceFromHash(hash);

        // THEN
        Assert.assertEquals(6, function.getLogarithmicRounds());
    }


    /**
     * Test method for 'BCrypt.gensalt(int)'
     */
    @Test
    public void testGensaltInt()
    {
        for (int i = 4; i <= 12; i++)
        {
            for (int j = 0; j < testObjectsString.size(); j += 4)
            {
                String plain = testObjectsString.get(j).password;
                BCryptFunction function = BCryptFunction.getInstance(10);
                String salt = function.generateSalt();
                Hash hashed1 = function.hash(plain, salt);
                Hash hashed2 = function.hash(plain, hashed1.getResult());
                Assert.assertEquals(hashed2.getResult(), hashed1.getResult());
            }
        }
    }

    @Test(expected = BadParametersException.class)
    public void generateBadSalt1()
    {
        BCryptFunction.generateSalt("S2", 10);
    }

    @Test(expected = BadParametersException.class)
    public void generateBadSalt2()
    {
        BCryptFunction.generateSalt("$2D", 10);
    }

    @Test(expected = BadParametersException.class)
    public void generateBadSalt3()
    {
        BCryptFunction.generateSalt("$2" + BCrypt.A.minor(), 3);
    }

    @Test(expected = BadParametersException.class)
    public void generateBadSalt4()
    {
        BCryptFunction.generateSalt("$2" + BCrypt.B.minor(), 32);
    }


    /**
     * Test method for 'BCrypt.checkpw(String, String)' expecting success
     */
    @Test
    public void testCheckpw_success()
    {

        for (TestObject<String> test : testObjectsString)
        {
            BCryptFunction function = BCryptFunction.getInstance(test.rounds);
            Assert.assertTrue(function.check(test.password, test.expected));
        }
    }


    /**
     * Test method for 'BCrypt.checkpw(String, String)' expecting failure
     */
    @Test
    public void testCheckpw_failure()
    {
        BCryptFunction function = BCryptFunction.getInstance(10);
        for (int i = 0; i < testObjectsString.size(); i++)
        {
            int broken_index = (i + 8) % testObjectsString.size();
            String plain = testObjectsString.get(i).password;
            String expected = testObjectsString.get(broken_index).expected;
            Assert.assertFalse(function.check(plain, expected));
        }
    }


    /**
     * Test for correct hashing of non-US-ASCII passwords
     */
    @Test
    public void testInternationalChars()
    {
        String pw1 = "ππππππππ";
        String pw2 = "????????";
        BCryptFunction function = BCryptFunction.getInstance(10);


        String h1 = function.hash(pw1).getResult();
        Assert.assertFalse(function.check(pw2, h1));

        String h2 = function.hash(pw2).getResult();
        Assert.assertFalse(function.check(pw1, h2));
    }


    @Test(expected = IllegalArgumentException.class)
    public void emptyByteArrayCannotBeEncoded()
    {
        BCryptFunction.encodeBase64(new byte[0], 0, new StringBuilder());
    }

    @Test(expected = IllegalArgumentException.class)
    public void moreBytesThanInTheArrayCannotBeEncoded()
    {
        BCryptFunction.encodeBase64(new byte[1], 2, new StringBuilder());
    }

    @Test(expected = IllegalArgumentException.class)
    public void decodingMustRequestMoreThanZeroBytes()
    {
        BCryptFunction.decodeBase64("", 0);
    }

    private static String encodeBase64(byte[] d, int len)
            throws IllegalArgumentException
    {
        StringBuilder rs = new StringBuilder();
        BCryptFunction.encodeBase64(d, len, rs);
        return rs.toString();
    }

    @Test
    public void testBase64EncodeSimpleByteArrays()
    {
        Assert.assertEquals("..", encodeBase64(new byte[]{0}, 1));
        Assert.assertEquals("...", encodeBase64(new byte[]{0, 0}, 2));
        Assert.assertEquals("....", encodeBase64(new byte[]{0, 0, 0}, 3));
    }

    @Test
    public void decodingCharsOutsideAsciiGivesNoResults()
    {
        byte[] ba = BCryptFunction.decodeBase64("ππππππππ", 1);
        Assert.assertEquals(0, ba.length);
    }

    @Test
    public void decodingStopsWithFirstInvalidCharacter()
    {
        Assert.assertEquals(1, BCryptFunction.decodeBase64("....", 1).length);
        Assert.assertEquals(0, BCryptFunction.decodeBase64(" ....", 1).length);
    }

    @Test
    public void decodingOnlyProvidesAvailableBytes()
    {
        Assert.assertEquals(0, BCryptFunction.decodeBase64("", 1).length);
        Assert.assertEquals(3, BCryptFunction.decodeBase64("......", 3).length);
        Assert.assertEquals(4, BCryptFunction.decodeBase64("......", 4).length);
        Assert.assertEquals(4, BCryptFunction.decodeBase64("......", 5).length);
    }

    /**
     * Encode and decode each byte value in each position.
     */
    @Test
    public void testBase64EncodeDecode()
    {
        byte[] byteArray = new byte[3];

        for (int aByte = 0; aByte <= 0xFF; aByte++)
        {
            for (int i = 0; i < byteArray.length; i++)
            {
                Arrays.fill(byteArray, (byte) 0);
                byteArray[i] = (byte) aByte;

                String s = encodeBase64(byteArray, 3);
                Assert.assertEquals(4, s.length());

                byte[] decoded = BCryptFunction.decodeBase64(s, 3);
                Assert.assertEquals(Arrays.toString(decoded), Arrays.toString(byteArray));
            }
        }
    }

    @Test(expected = BadParametersException.class)
    public void testBadSalt1()
    {
        // GIVEN
        String password = "password";
        String badSalt1 = "2b$06$ehKGYiS4wt2HAr7KQXS5z.";

        // WHEN
        BCryptFunction.getInstance(10).hash(password, badSalt1);
    }

    @Test(expected = BadParametersException.class)
    public void testBadSalt2()
    {
        // GIVEN
        String password = "password";
        String badSalt2 = "$2b06$ehKGYiS4wt2HAr7KQXS5z.";

        // WHEN
        BCryptFunction.getInstance(6).hash(password, badSalt2);
    }

    @Test(expected = BadParametersException.class)
    public void testBadSalt3()
    {
        // GIVEN
        String password = "password";
        String badSalt3 = "$2d$06$ehKGYiS4wt2HAr7KQXS5z.";

        // WHEN
        BCryptFunction.getInstance(6).hash(password, badSalt3);
    }

    @Test(expected = BadParametersException.class)
    public void testBadSalt4()
    {
        // GIVEN
        String password = "password";
        String badSalt3 = "$2b$06%ehKGYiS4wt2HAr7KQXS5z.";

        // WHEN
        BCryptFunction.getInstance(10).hash(password, badSalt3);
    }


    @Test(expected = BadParametersException.class)
    public void testBadSalt5()
    {
        // GIVEN
        String password = "password";
        String badSalt3 = "$2b$06%ehKGYiS4wt2HAr7KQXS5z.";

        // WHEN
        BCryptFunction.getInstance(10).cryptRaw(password.getBytes(), badSalt3.getBytes(), 6, false, 1);
    }


    @Test
    public void genSaltGeneratesCorrectSaltPrefix()
    {
        Assert.assertTrue(StringUtils.startsWith(BCryptFunction.getInstance(4).hash("").getResult(), "$2a$04$"));
        Assert.assertTrue(StringUtils.startsWith(BCryptFunction.getInstance(31).hash("").getResult(), "$2a$31$"));
    }

    @Test(expected = BadParametersException.class)
    public void hashpwFailsWhenSaltIsNull()
    {
        BCryptFunction.getInstance(10).hash("password", null);
    }

    @Test(expected = BadParametersException.class)
    public void hashpwFailsWhenSaltSpecifiesTooFewRounds()
    {
        BCryptFunction.getInstance(3).hash("password", "$2a$03$......................");
    }

    @Test(expected = BadParametersException.class)
    public void hashpwFailsWhenSaltSpecifiesTooManyRounds()
    {
        BCryptFunction.getInstance(32).hash("password", "$2a$32$......................");
    }

    @Test(expected = BadParametersException.class)
    public void saltLengthIsChecked()
    {
        BCryptFunction.getInstance(10).hash("", "");
    }

    @Test
    public void hashpwWorksWithOldRevision()
    {
        Assert.assertEquals("$2$05$......................bvpG2UfzdyW/S0ny/4YyEZrmczoJfVm", BCryptFunction.getInstance(5).hash("password", "$2$05$......................").getResult());
    }

    @Test(expected = BadParametersException.class)
    public void hashpwFailsWhenSaltIsTooShort()
    {
        BCryptFunction.getInstance(10).hash("password", "$2a$10$123456789012345678901");
    }

    @Test
    public void equalsOnStringsIsCorrect()
    {
        Assert.assertTrue(BCryptFunction.equalsNoEarlyReturn("", ""));
        Assert.assertTrue(BCryptFunction.equalsNoEarlyReturn("test", "test"));

        Assert.assertFalse(BCryptFunction.equalsNoEarlyReturn("test", ""));
        Assert.assertFalse(BCryptFunction.equalsNoEarlyReturn("", "test"));

        Assert.assertFalse(BCryptFunction.equalsNoEarlyReturn("test", "pass"));
    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        int logRounds = 7;
        BCrypt type = BCrypt.Y;

        // WHEN
        BCryptFunction bcrypt = BCryptFunction.getInstance(type, logRounds);

        // THEN
        Assert.assertEquals(logRounds, bcrypt.getLogarithmicRounds());
        Assert.assertEquals(type, bcrypt.getType());
        Assert.assertEquals("BCryptFunction[y|7]", bcrypt.toString());
    }

}
