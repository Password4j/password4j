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
import java.util.Set;


/**
 * This class benchmarks the target environment.
 *
 * @author David Bertoldi
 * @since 1.0.0
 */
public class SystemChecker
{
    private static final String TO_BE_HASHED = "abcDEF123@~# xyz+-*/=456spqr";

    private static final String SALT = new String(SaltGenerator.generate());

    private static final int WARMUP_ROUNDS = 20;

    private SystemChecker()
    {
        //
    }

    /**
     * Verifies if the algorithm is supported by the current environment.
     * PBKDF2 variants are available if the JVM has a corresponding
     * {@link java.security.Provider.Service}
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is supported; false otherwise
     */
    public static boolean isPBKDF2Supported(String algorithm)
    {
        if (algorithm == null)
        {
            throw new BadParametersException("Algorithm cannot be null.");
        }
        List<String> variants = AlgorithmFinder.getAllPBKDF2Variants();
        return variants.stream().anyMatch(algorithm::equals);
    }

    /**
     * Verifies if the algorithm is supported by the current environment.
     * Message digest algorithms are available if the JVM has a corresponding
     * {@link java.security.Provider.Service}
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is supported; false otherwise
     */
    public static boolean isMessageDigestSupported(String algorithm)
    {
        if (algorithm == null)
        {
            throw new BadParametersException("Algorithm cannot be null.");
        }
        Set<String> mds = AlgorithmFinder.getAllMessageDigests();
        return mds.stream().anyMatch(algorithm::equals);
    }

    /**
     * Finds the optimal logarithmic cost of BCrypt.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @return the logarithmic cost
     * @see BCryptFunction
     * @since 1.0.0
     */
    public static int findRoundsForBCrypt(long maxMilliseconds)
    {
        warmUpBCrypt();

        long elapsed;
        int rounds = 3;
        do
        {
            rounds++;
            long start = System.currentTimeMillis();

            new BCryptFunction(BCrypt.A, rounds).hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            elapsed = end - start;

        } while (elapsed <= maxMilliseconds);

        return rounds - 1;
    }


    /**
     * Finds the optimal number of iterations for PBKDF2.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @param algorithm       the chosen variant
     * @param length          it is recommended to use {@link Hmac#bits()}
     * @return number of iterations
     * @see PBKDF2Function
     * @since 1.0.0
     */
    public static int findIterationsForPBKDF2(long maxMilliseconds, Hmac algorithm, int length)
    {
        warmUpPBKDF2(algorithm, length);

        long elapsed;
        int iterations = 1;
        do
        {
            iterations += 150;
            long start = System.currentTimeMillis();

            new PBKDF2Function(algorithm, iterations, length).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;

        } while (elapsed <= maxMilliseconds);


        return iterations - 100;
    }

    /**
     * Finds the optimal work factor (N) for SCrypt.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @param resources       r parameter
     * @param parallelization p parameter
     * @return the optimal work factor (N)
     * @since 1.0.0
     */
    public static int findWorkFactorForSCrypt(long maxMilliseconds, int resources, int parallelization)
    {

        int workFactor = 2;
        warmUpSCrypt(workFactor, resources, parallelization);

        long elapsed;
        do
        {
            workFactor *= 2;
            long start = System.currentTimeMillis();

            new SCryptFunction(workFactor, resources, parallelization).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;


        } while (elapsed <= maxMilliseconds);


        return workFactor / 2;
    }

    /**
     * Finds the optimal resources (r) for SCrypt.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @param workFactor      N parameter
     * @param parallelization p parameter
     * @return the optimal resources (r)
     * @since 1.0.0
     */
    public static int findResourcesForSCrypt(long maxMilliseconds, int workFactor, int parallelization)
    {
        warmUpSCrypt(workFactor, 1, parallelization);

        long elapsed;
        int resources = 0;
        do
        {
            resources += 1;
            long start = System.currentTimeMillis();

            new SCryptFunction(workFactor, resources, parallelization).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;


        } while (elapsed <= maxMilliseconds);


        return resources - 1;
    }


    private static void warmUpBCrypt()
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            BCryptFunction.getInstance(4).hash(TO_BE_HASHED);
        }
    }

    private static void warmUpPBKDF2(Hmac algorithm, int length)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            PBKDF2Function.getInstance(algorithm, 1, length).hash(TO_BE_HASHED, SALT);
        }
    }

    private static void warmUpSCrypt(int workFactor, int resources, int parallelization)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            SCryptFunction.getInstance(workFactor, resources, parallelization).hash(TO_BE_HASHED);
        }
    }


}
