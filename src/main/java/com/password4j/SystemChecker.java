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

import java.util.List;

public class SystemChecker
{
    private static final String TO_BE_HASHED = "abcDEF123@~# xyz+-*/=456spqr";

    private static final String SALT = new String(SaltGenerator.generate());

    private static final int WARMUP_ROUNDS = 20;

    private SystemChecker()
    {
        //
    }


    public static boolean isPBKDF2Supported(PBKDF2Function.Algorithm algorithm)
    {
        if (algorithm == null)
        {
            throw new BadParametersException("Algorithm cannot be null.");
        }
        List<String> variants = AlgorithmFinder.getAllPBKDF2Variants();
        return variants.stream().anyMatch(v -> algorithm.name().equals(v));
    }

    public static int findRoundsForBCrypt(long maxMilliseconds)
    {
        warmUpBCrypt();

        long elapsed;
        int rounds = 3;
        do
        {
            rounds++;
            long start = System.currentTimeMillis();

            new BCryptFunction(rounds).hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            elapsed = end - start;

        } while (elapsed <= maxMilliseconds);

        return rounds - 1;
    }


    public static int findIterationsForPBKDF2(long maxMilliseconds, PBKDF2Function.Algorithm algorithm, int length)
    {
        warmUpPBKDF2(algorithm, length);

        long elapsed;
        int iterations = 1;
        do
        {
            iterations += 100;
            long start = System.currentTimeMillis();

            new PBKDF2Function(algorithm, iterations, length).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;

        } while (elapsed <= maxMilliseconds);

        return iterations - 1;
    }


    private static void warmUpBCrypt()
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            BCryptFunction.getInstance(4).hash(TO_BE_HASHED);
        }
    }

    private static void warmUpPBKDF2(PBKDF2Function.Algorithm algorithm, int length)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            PBKDF2Function.getInstance(algorithm, 1, length).hash(TO_BE_HASHED, SALT);
        }
    }

}
