/*
 *  (C) Copyright 2023 Password4j (http://password4j.com/).
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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class BalloonHashingFunctionTest
{

    private static final Object[][] TEST_VECTORS = new Object[][]{
            // Single thread
            new Object[]{"hunter42", "examplesalt", "SHA-256", 1024, 3, 0, 3, "716043dff777b44aa7b88dcbab12c078abecfac9d289c5b5195967aa63440dfb"},
            new Object[]{"", "salt", "SHA-256", 3, 3, 0, 3, "5f02f8206f9cd212485c6bdf85527b698956701ad0852106f94b94ee94577378"},
            new Object[]{"password", "", "SHA-256", 3, 3, 0, 3, "20aa99d7fe3f4df4bd98c655c5480ec98b143107a331fd491deda885c4d6a6cc"},
            new Object[]{"\0", "\0", "SHA-256", 3, 3, 0, 3, "4fc7e302ffa29ae0eac31166cee7a552d1d71135f4e0da66486fb68a749b73a4"},
            new Object[]{"password", "salt", "SHA-256", 1, 1, 0, 3, "eefda4a8a75b461fa389c1dcfaf3e9dfacbc26f81f22e6f280d15cc18c417545"},

            // Multiple threads
            new Object[]{"hunter42", "examplesalt", "SHA-256", 1024, 3, 4, 3, "1832bd8e5cbeba1cb174a13838095e7e66508e9bf04c40178990adbc8ba9eb6f"},
            new Object[]{"", "salt", "SHA-256", 3, 3, 2, 3, "f8767fe04059cef67b4427cda99bf8bcdd983959dbd399a5e63ea04523716c23"},
            new Object[]{"password", "", "SHA-256", 3, 3, 3, 3, "bcad257eff3d1090b50276514857e60db5d0ec484129013ef3c88f7d36e438d6"},
            new Object[]{"password", "", "SHA-256", 3, 3, 1, 3, "498344ee9d31baf82cc93ebb3874fe0b76e164302c1cefa1b63a90a69afb9b4d"},
            new Object[]{"\000", "\000", "SHA-256", 3, 3, 4, 3, "8a665611e40710ba1fd78c181549c750f17c12e423c11930ce997f04c7153e0c"},
            new Object[]{"\000", "\000", "SHA-256", 3, 3, 1, 3, "d9e33c683451b21fb3720afbd78bf12518c1d4401fa39f054b052a145c968bb1"},
            new Object[]{"password", "salt", "SHA-256", 1, 1, 16, 3, "a67b383bb88a282aef595d98697f90820adf64582a4b3627c76b7da3d8bae915"},
            new Object[]{"password", "salt", "SHA-256", 1, 1, 1, 3, "97a11df9382a788c781929831d409d3599e0b67ab452ef834718114efdcd1c6d"},

    };


    @Test
    public void test()
    {

        BalloonHashingFunction balloonHashingFunction;
        for (Object[] testVector : TEST_VECTORS)
        {
            balloonHashingFunction = new BalloonHashingFunction((String) testVector[2], (Integer) testVector[3], (Integer) testVector[4], (Integer) testVector[5], (Integer) testVector[6]);
            Assert.assertEquals(testVector[7], balloonHashingFunction.hash((String) testVector[0], (String) testVector[1]).getResult());

            Assert.assertTrue(balloonHashingFunction.check((String) testVector[0], (String) testVector[7], (String) testVector[1]));
        }

    }

    @Test
    public void testInstance()
    {

        BalloonHashingFunction balloonHashingFunction;
        for (Object[] testVector : TEST_VECTORS)
        {
            balloonHashingFunction = BalloonHashingFunction.getInstance((String) testVector[2], (Integer) testVector[3], (Integer) testVector[4], (Integer) testVector[5], (Integer) testVector[6]);
            Assert.assertEquals(testVector[7], balloonHashingFunction.hash((String) testVector[0], (String) testVector[1]).getResult());
            Assert.assertEquals(testVector[7], balloonHashingFunction.hash(((String) testVector[0]).getBytes(), ((String) testVector[1]).getBytes()).getResult());

            Assert.assertTrue(balloonHashingFunction.check((String) testVector[0], (String) testVector[7], (String) testVector[1]));
            Assert.assertTrue(balloonHashingFunction.check(((String) testVector[0]).getBytes(), ((String) testVector[7]).getBytes(), ((String) testVector[1]).getBytes()));
        }

    }

    @Test
    public void testEquality()
    {
        // GIVEN
        String m = "SHA-256";
        int i = 2;
        int p = 3;
        int l = 4;
        int v = 5;
        BalloonHashingFunction balloonHashingFunction = BalloonHashingFunction.getInstance(m, i, p, l, v);

        // THEN
        boolean eqNull = balloonHashingFunction.equals(null);
        boolean eqClass = balloonHashingFunction.equals(new BcryptFunction(Bcrypt.A, 10));
        boolean sameInst = balloonHashingFunction.equals(BalloonHashingFunction.getInstance(m, i, p, l, v));
        boolean sameInst2 = balloonHashingFunction.equals(new BalloonHashingFunction(m, i, p, l, v));
        String toString = balloonHashingFunction.toString();
        int hashCode = balloonHashingFunction.hashCode();
        boolean notSameInst1 = balloonHashingFunction.equals(new BalloonHashingFunction("SHA-512", i, p, l, v));
        boolean notSameInst2 = balloonHashingFunction.equals(new BalloonHashingFunction(m, i+1, p, l, v));
        boolean notSameInst3 = balloonHashingFunction.equals(new BalloonHashingFunction(m, i, p+1, l, v));
        boolean notSameInst4 = balloonHashingFunction.equals(new BalloonHashingFunction(m, i, p, l+1, v));
        boolean notSameInst6 = balloonHashingFunction.equals(new BalloonHashingFunction(m, i, p, l,  v+1));

        // END
        Assert.assertFalse(eqNull);
        Assert.assertFalse(eqClass);
        Assert.assertTrue(sameInst);
        Assert.assertTrue(sameInst2);
        Assert.assertNotEquals(toString, new BalloonHashingFunction(m, i+1, p, l, v).toString());
        Assert.assertNotEquals(hashCode, new BalloonHashingFunction(m, i, p, l, v+1).hashCode());
        Assert.assertFalse(notSameInst1);
        Assert.assertFalse(notSameInst2);
        Assert.assertFalse(notSameInst3);
        Assert.assertFalse(notSameInst4);
        Assert.assertFalse(notSameInst6);
    }

}
