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

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class SystemChecker
{
    private static final Logger LOG = LoggerFactory.getLogger(SystemChecker.class);

    private static final String TO_BE_HASHED = "abcDEF123@~# xyz+-*/=456spqr";

    private static final String SALT = new String(SaltGenerator.generate());

    private static final int WARMUP_ROUNDS = 20;

    private SystemChecker()
    {
        //
    }

    public static void main(String... args)
    {
        println("Please choose the CHF you want to optimize for your system.");
        println(" - PBKDF2");
        println(" - BCrypt");
        println(" - SCrypt");
        String choice = ask("Choice: ");

        switch (choice)
        {
            case "PBKDF2":
                managePBKDF2();
                break;
            case "BCrypt":
                manageBCrypt();
                break;
            case "SCrypt":
                manageSCrypt();
                break;
            default:
                println(choice + " is not a supported CHF.");
                System.exit(1);
        }
        System.exit(0);
    }

    private static void managePBKDF2()
    {
        println("These are the supported PBKDF2 algorithms by your environment");
        List<String> variants = AlgorithmFinder.getAllPBKDF2Variants();
        StringBuilder listSB = new StringBuilder(variants.size());
        for (String variant : variants)
        {
            listSB.append(" - ").append(variant).append(System.lineSeparator());
        }
        println(listSB.toString());
        String chosenVariant = ask("Please choose one: ");
        String suffix = chosenVariant.replace("PBKDF2WithHmac", "");
        PBKDF2Function.Algorithm algorithm = PBKDF2Function.Algorithm.valueOf(suffix);
        println("The recommended length of the derived key is " + algorithm.bits() + " bits.");
        String millis = ask("Please enter a maximum execution time for password hashing (in milliseconds): ");
        long maxMillis = Long.parseLong(millis);
        int iterations = findIterationsForPBKDF2(maxMillis, algorithm, algorithm.bits());

        println("Use the following configurations in your psw4j.properties file" + System.lineSeparator());

        println("   hash.pbkdf2.algorithm=" + suffix);
        println("   hash.pbkdf2.iterations=" + iterations);
        println("   hash.pbkdf2.length=" + algorithm.bits());

    }

    private static void manageBCrypt()
    {
        String millis = ask("Please enter a maximum execution time for password hashing (in milliseconds): ");
        long maxMillis = Long.parseLong(millis);
        int logRounds = findRoundsForBCrypt(maxMillis);

        println("Use the following configurations in your psw4j.properties file" + System.lineSeparator());

        println("   hash.bcrypt.rounds=" + logRounds);
    }

    private static void manageSCrypt()
    {
        String parallelization = ask("Please choose the parallelization (p) parameter: ");
        int p = Integer.parseInt(parallelization);

        String millis = ask("Please enter a maximum execution time for password hashing (in milliseconds): ");
        long maxMillis = Long.parseLong(millis);

        int n = findWorkingFactoryForSCrypt(maxMillis, 14, p);
        int r = findResourcesForSCrypt(maxMillis, n, p);

        println("Estimated memory required for this configuration: " + new SCryptFunction(n, r, p).getRequiredMemory());


        println("Use the following configurations in your psw4j.properties file" + System.lineSeparator());

        println("   hash.scrypt.workfactor=" + n);
        println("   hash.scrypt.resources=" + r);
        println("   hash.scrypt.parallelization=" + p);
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

        StringBuilder report = new StringBuilder()
                .append(System.lineSeparator())
                .append("BCrypt")
                .append(" under ")
                .append(maxMilliseconds)
                .append("ms")
                .append(System.lineSeparator());

        long elapsed;
        int rounds = 3;
        do
        {
            rounds++;
            long start = System.currentTimeMillis();

            new BCryptFunction(rounds).hash(TO_BE_HASHED);

            long end = System.currentTimeMillis();
            elapsed = end - start;

            report.append(" * logRounds: ")
                    .append(rounds)
                    .append(" -> ")
                    .append(elapsed)
                    .append("ms")
                    .append(System.lineSeparator());

        } while (elapsed <= maxMilliseconds);

        int finalRounds = rounds - 1;

        report.append("*** Final result: ")
                .append(finalRounds)
                .append(" logRounds under ")
                .append(maxMilliseconds)
                .append("ms ***")
                .append(System.lineSeparator());

        if (LOG.isInfoEnabled())
        {
            LOG.info(report.toString());
        }
        println(report.toString()); // NOSONAR

        return finalRounds;
    }


    public static int findIterationsForPBKDF2(long maxMilliseconds, PBKDF2Function.Algorithm algorithm, int length)
    {
        warmUpPBKDF2(algorithm, length);

        String title = System.lineSeparator() +
                "Finding the number of iterations for PBKDF2 with algorithm=PBKDF2WithHmac" +
                algorithm.name() +
                " and length=" +
                length +
                " under " +
                maxMilliseconds +
                "ms" +
                System.lineSeparator();
        println(title);


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

        int finalIterations = iterations - 100;

        StringBuilder result = new StringBuilder()
                .append("*** Final result: ")
                .append(finalIterations)
                .append(" iterations under ")
                .append(maxMilliseconds)
                .append("ms ***")
                .append(System.lineSeparator());

        if (LOG.isInfoEnabled())
        {
            LOG.info(result.toString());
        }
        println(result.toString());

        return finalIterations;
    }

    public static int findWorkingFactoryForSCrypt(long maxMilliseconds, int resources, int parallelization)
    {

        warmUpSCrypt(2, resources, parallelization);

        StringBuilder report = new StringBuilder()
                .append(System.lineSeparator())
                .append("SCrypt with r=")
                .append(resources)
                .append(" and p=")
                .append(parallelization)
                .append(" under ")
                .append(maxMilliseconds)
                .append("ms")
                .append(System.lineSeparator());

        long elapsed;
        int workFactor = 1;
        do
        {
            workFactor *= 2;
            long start = System.currentTimeMillis();

            new SCryptFunction(workFactor, resources, parallelization).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;

            report.append(" - workFactor: ")
                    .append(workFactor)
                    .append(" -> ")
                    .append(elapsed)
                    .append("ms")
                    .append(System.lineSeparator());

        } while (elapsed <= maxMilliseconds);


        int finalWorkFactor = workFactor / 2;

        report.append("*** Final result: ")
                .append(finalWorkFactor)
                .append(" workFactor (N) under ")
                .append(maxMilliseconds)
                .append("ms ***");

        if (LOG.isInfoEnabled())
        {
            LOG.info(report.toString());
        }
        println(report.toString()); // NOSONAR

        return finalWorkFactor;
    }

    public static int findResourcesForSCrypt(long maxMilliseconds, int workFactor, int parallelization)
    {
        warmUpSCrypt(workFactor, 1, parallelization);

        StringBuilder report = new StringBuilder()
                .append(System.lineSeparator())
                .append("SCrypt with N=")
                .append(workFactor)
                .append(" and p=")
                .append(parallelization)
                .append(" under ")
                .append(maxMilliseconds)
                .append("ms")
                .append(System.lineSeparator());

        long elapsed;
        int resources = 0;
        do
        {
            resources += 1;
            long start = System.currentTimeMillis();

            new SCryptFunction(workFactor, resources, parallelization).hash(TO_BE_HASHED, SALT);

            long end = System.currentTimeMillis();
            elapsed = end - start;

            report.append(" - resources: ")
                    .append(resources)
                    .append(" -> ")
                    .append(elapsed)
                    .append("ms")
                    .append(System.lineSeparator());

        } while (elapsed <= maxMilliseconds);

        int finalResources = resources - 1;

        report.append("*** Final result: ")
                .append(finalResources)
                .append(" resources (r) under ")
                .append(maxMilliseconds)
                .append("ms ***")
                .append(System.lineSeparator());

        if (LOG.isInfoEnabled())
        {
            LOG.info(report.toString());
        }
        println(report.toString()); // NOSONAR

        return finalResources;
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

    private static void warmUpSCrypt(int workFactor, int resources, int parallelization)
    {
        for (int i = 0; i < WARMUP_ROUNDS; i++)
        {
            SCryptFunction.getInstance(workFactor, resources, parallelization).hash(TO_BE_HASHED);
        }
    }

    private static void println(String message)
    {
        if (System.console() != null && System.console().writer() != null)
        {
            System.console().writer().println(message);
        }
    }


    private static String ask(String message)
    {
        println(message);
        return StringEscapeUtils.escapeJava(System.console().readLine());
    }


}
