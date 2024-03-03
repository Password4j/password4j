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
        long maxMilliseconds = 10;

        // WHEN
        BenchmarkResult<PBKDF2Function> result = SystemChecker.benchmarkPBKDF2(maxMilliseconds, Hmac.SHA256, 256);

        // THEN
        Assert.assertTrue(result.getPrototype().getIterations() > 150);
        Assert.assertTrue(result.getElapsed() <= maxMilliseconds);
    }

    @Test
    public void testPBKDF2Iterations2()
    {
        // GIVEN
        long maxMilliseconds = -1;

        // WHEN
        BenchmarkResult<PBKDF2Function> result = SystemChecker.benchmarkPBKDF2(maxMilliseconds, Hmac.SHA512, 4096);

        // THEN
        Assert.assertNull(result.getPrototype());
        Assert.assertEquals(-1, result.getElapsed());
    }


    @Test
    public void testArgon2Iterations()
    {
        // GIVEN
        long maxMilliseconds = 50;
        int memoryForEachHash = 512;
        int threadsPerHash = 2;
        int outputLength = 128;
        Argon2 type = Argon2.ID;

        // WHEN
        BenchmarkResult<Argon2Function> result = SystemChecker.benchmarkForArgon2(maxMilliseconds, memoryForEachHash, threadsPerHash, outputLength, type);

        // THEN
        Assert.assertTrue(result.getPrototype().getIterations() > 1);
        Assert.assertTrue(result.getElapsed() <= maxMilliseconds);
    }

    @Test
    public void testArgon2Iterations2()
    {
        // GIVEN
        long maxMilliseconds = 2;
        int memoryForEachHash = 4096;
        int threadsPerHash = 21;
        int outputLength = 128;
        Argon2 type = Argon2.ID;

        // WHEN
        BenchmarkResult<Argon2Function> result = SystemChecker.benchmarkForArgon2(maxMilliseconds, memoryForEachHash, threadsPerHash, outputLength, type);

        // THEN
        Assert.assertNull(result.getPrototype());
        Assert.assertEquals(-1, result.getElapsed());
    }


    @Test
    public void testBcryptRounds()
    {
        // GIVEN
        long maxMilliseconds = 50;

        // WHEN
        BenchmarkResult<BcryptFunction> result = SystemChecker.benchmarkBcrypt(maxMilliseconds);

        // THEN
        Assert.assertTrue(result.getPrototype().getLogarithmicRounds() >= 4);
        Assert.assertTrue(result.getElapsed() <= maxMilliseconds);
    }

    @Test
    public void testBcryptRounds2()
    {
        // GIVEN
        long maxMilliseconds = -1;

        // WHEN
        BenchmarkResult<BcryptFunction> result = SystemChecker.benchmarkBcrypt(maxMilliseconds);

        // THEN
        Assert.assertNull(result.getPrototype());
        Assert.assertEquals(-1, result.getElapsed());
    }

    @Test
    public void testScryptRounds()
    {
        // GIVEN
        long maxMilliseconds = -1;

        // WHEN
        BenchmarkResult<ScryptFunction> result1 = SystemChecker.findWorkFactorForScrypt(maxMilliseconds, 16, 1);
        BenchmarkResult<ScryptFunction> result2 = SystemChecker.findResourcesForScrypt(maxMilliseconds, 1024, 1);

        // THEN
        Assert.assertNull(result1.getPrototype());
        Assert.assertEquals(-1, result1.getElapsed());
        Assert.assertNull(result2.getPrototype());
        Assert.assertEquals(-1, result2.getElapsed());
    }

    @Test
    public void testScryptRounds2()
    {
        // GIVEN
        long maxMilliseconds = 50;

        // WHEN
        BenchmarkResult<ScryptFunction> result1 = SystemChecker.findWorkFactorForScrypt(maxMilliseconds, 16, 1);
        BenchmarkResult<ScryptFunction> result2 = SystemChecker.findResourcesForScrypt(maxMilliseconds, result1.getPrototype().getWorkFactor(), 1);

        // THEN
        Assert.assertTrue(result1.getElapsed() > 0);
        Assert.assertTrue(result2.getElapsed() > 0);
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
