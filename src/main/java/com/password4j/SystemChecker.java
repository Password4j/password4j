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
import com.password4j.types.Hmac;

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

    private static final String SALT = Utils.fromBytesToString(SaltGenerator.generate());

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
        for (String variant : variants)
        {
            if (algorithm.equals(variant))
            {
                return true;
            }
        }
        return false;
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
        for (String md : mds)
        {
            if (algorithm.equals(md))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Finds the optimal configuration for bcrypt.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     * <p>
     * This function returns a prototype {@link BcryptFunction} and the real
     * elapsed time.
     * If the hash cannot be performed under the specified time, the elapsed time is set to -1
     * and prototype null.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @return a benchmark result for bcrypt
     * @see BcryptFunction
     * @since 1.0.0
     */
    @SuppressWarnings("Duplicates")
    public static BenchmarkResult<BcryptFunction> benchmarkBcrypt(long maxMilliseconds)
    {
        warmUpBcrypt();

        long finalElapsed = -1;
        BcryptFunction prototype = null;
        int rounds = 4;

        while (true)
        {
            BcryptFunction tmp = new BcryptFunction(Bcrypt.B, rounds);
            long start = System.currentTimeMillis();

            tmp.hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            long elapsed = end - start;

            if (elapsed > maxMilliseconds)
            {
                break;
            }
            else
            {
                finalElapsed = elapsed;
                prototype = tmp;
                rounds++;
            }
        }

        return new BenchmarkResult<>(prototype, finalElapsed);
    }

    /**
     * Finds the optimal configuration for Argon2.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     * <p>
     * This function returns a prototype {@link Argon2Function} and the real
     * elapsed time.
     * If the hash cannot be performed under the specified time, the elapsed time is set to -1
     * and prototype null.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @param memory          logarithmic memory
     * @param parallelism     level of parallelism
     * @param outputLength    length of the final hash
     * @param type            argon2 type (i, d or id)
     * @return a benchmark result for bcrypt
     * @see Argon2Function
     * @since 1.5.0
     */
    @SuppressWarnings("Duplicates")
    public static BenchmarkResult<Argon2Function> benchmarkForArgon2(long maxMilliseconds, int memory, int parallelism,
                                                                     int outputLength, Argon2 type)
    {
        warmUpArgon2();

        long finalElapsed = -1;
        Argon2Function prototype = null;
        int iterations = 1;

        while (true)
        {
            Argon2Function tmp = new Argon2Function(memory, iterations, parallelism, outputLength, type,
                    Argon2Function.ARGON2_VERSION_13);

            long start = System.currentTimeMillis();

            tmp.hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            long elapsed = end - start;

            if (elapsed > maxMilliseconds)
            {
                break;
            }
            else
            {
                finalElapsed = elapsed;
                prototype = tmp;
                iterations++;
            }
        }

        if (finalElapsed == -1 && memory <= 4)
        {
            return benchmarkForArgon2(maxMilliseconds, memory / 2, parallelism, outputLength, type);
        }

        return new BenchmarkResult<>(prototype, finalElapsed);

    }

    /**
     * Finds the optimal configuration for PBKDF2.
     * <p>
     * To prevent timing attacks, a maximum interval of time (in milliseconds)
     * is required to perform a single hash.
     * <p>
     * This function returns a prototype {@link PBKDF2Function} and the real
     * elapsed time.
     * If the hash cannot be performed under the specified time, the elapsed time is set to -1
     * and prototype null.
     *
     * @param maxMilliseconds max time to perform the hashing
     * @param algorithm       the chosen variant
     * @param length          it is recommended to use {@link Hmac#bits()}
     * @return a benchmark result for bcrypt
     * @see PBKDF2Function
     * @since 1.0.0
     */
    public static BenchmarkResult<PBKDF2Function> benchmarkPBKDF2(long maxMilliseconds, Hmac algorithm, int length)
    {
        warmUpPBKDF2(algorithm, length);

        long finalElapsed = -1;
        int iterations = 150;
        PBKDF2Function prototype = null;

        while (true)
        {
            PBKDF2Function tmp = new PBKDF2Function(algorithm, iterations, length);
            long start = System.currentTimeMillis();

            tmp.hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            long elapsed = end - start;

            if (elapsed > maxMilliseconds)
            {
                break;
            }
            else
            {
                finalElapsed = elapsed;
                prototype = tmp;
                iterations += 150;
            }
        }

        return new BenchmarkResult<>(prototype, finalElapsed);
    }

    /**
     * Finds the optimal work factor (N) for scrypt.
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
    public static BenchmarkResult<ScryptFunction> findWorkFactorForScrypt(long maxMilliseconds, int resources,
                                                                          int parallelization)
    {
        int workFactor = 2;
        warmUpScrypt(workFactor, parallelization);

        long finalElapsed = -1;
        ScryptFunction prototype = null;

        while (true)
        {
            ScryptFunction tmp = new ScryptFunction(workFactor, resources, parallelization);
            long start = System.currentTimeMillis();

            tmp.hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            long elapsed = end - start;

            if (elapsed > maxMilliseconds)
            {
                break;
            }
            else
            {
                finalElapsed = elapsed;
                prototype = tmp;
                workFactor *= 2;
            }
        }

        return new BenchmarkResult<>(prototype, finalElapsed);
    }

    /**
     * Finds the optimal resources (r) for scrypt.
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
    public static BenchmarkResult<ScryptFunction> findResourcesForScrypt(long maxMilliseconds, int workFactor,
                                                                         int parallelization)
    {
        warmUpScrypt(workFactor, parallelization);

        int resources = 1;
        long finalElapsed = -1;
        ScryptFunction prototype = null;

        while (true)
        {
            ScryptFunction tmp = new ScryptFunction(workFactor, resources, parallelization);
            long start = System.currentTimeMillis();

            tmp.hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            long elapsed = end - start;

            if (elapsed > maxMilliseconds)
            {
                break;
            }
            else
            {
                finalElapsed = elapsed;
                prototype = tmp;
                resources++;
            }
        }

        return new BenchmarkResult<>(prototype, finalElapsed);
    }

    private static void warmUpBcrypt()
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            BcryptFunction.getInstance(4).hash(TO_BE_HASHED);
        }
    }

    private static void warmUpArgon2()
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            Argon2Function.getInstance(8, 1, 1, 32, Argon2.ID).hash(TO_BE_HASHED);
        }
    }

    private static void warmUpPBKDF2(Hmac algorithm, int length)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            PBKDF2Function.getInstance(algorithm, 1, length).hash(TO_BE_HASHED, SALT);
        }
    }

    private static void warmUpScrypt(int workFactor, int parallelization)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            ScryptFunction.getInstance(workFactor, 1, parallelization).hash(TO_BE_HASHED);
        }
    }

}
