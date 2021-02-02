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
import com.password4j.types.Hmac;
import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public class SystemCheckTest
{

    @Test
    public void testPBKDF2Iterations()
    {
        // GIVEN

        // WHEN
        int result = SystemChecker.findIterationsForPBKDF2(10, Hmac.SHA256, 256);

        // THEN
        Assert.assertTrue(result > 0);
    }


    @Test
    public void testArgon2Iterations()
    {
        // GIVEN
        int memoryForEachHash = 4096;
        int threadsPerHash = 2;
        int outputLength = 128;
        Argon2 type = Argon2.ID;

        // WHEN
        int result = SystemChecker.findIterationsForArgon2(50, memoryForEachHash, threadsPerHash, outputLength, type);

        // THEN
        Assert.assertTrue(result > 0);
    }


    @Test
    public void testBCryptRounds()
    {
        // GIVEN

        // WHEN
        int result = SystemChecker.findRoundsForBCrypt(50);

        // THEN
        Assert.assertTrue(result > 0);
    }

    @Test
    public void testSCryptRounds()
    {
        // GIVEN
        long maxMilliseconds = 1;

        // WHEN
        int result1 = SystemChecker.findWorkFactorForSCrypt(maxMilliseconds, 16, 1);
        int result2 = SystemChecker.findResourcesForSCrypt(maxMilliseconds, result1, 1);

        // THEN
        Assert.assertTrue(result1 > 0);
        Assert.assertTrue(result2 > 0);
    }

    @Test(expected = BadParametersException.class)
    public void testWrongVariants()
    {
        //GIVEN

        // WHEN
        SystemChecker.isPBKDF2Supported(null);
    }

    @Test(expected = Test.None.class)
    public void testVariants()
    {
        //GIVEN

        // WHEN
       SystemChecker.isPBKDF2Supported(Hmac.SHA256.name());
    }


    @Test(expected = BadParametersException.class)
    public void testWrongAlgs()
    {
        //GIVEN

        // WHEN
        SystemChecker.isMessageDigestSupported(null);
    }

    @Test
    public void testAlgs()
    {
        //GIVEN

        // WHEN
        Set<String> mds = AlgorithmFinder.getAllMessageDigests();
        for(String md : mds)
        {
            Assert.assertTrue(SystemChecker.isMessageDigestSupported(md));
        }

    }




}
