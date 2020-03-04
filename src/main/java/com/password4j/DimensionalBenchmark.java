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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class DimensionalBenchmark
{

    private static final String TO_BE_HASHED = "abcDEF123@~# xyz+-*/=456spqr";

    private static final int LOOPS = 20;

    private static final int[] PBKDF2_ROUNDS = new int[]{10_000, 32_000, 64_000};

    private static final Comparator<Result<PBKDF2Function>> pbkdf2Comparator = (r1, r2) -> {
        PBKDF2Function f1 = r1.getHashingFunction();
        PBKDF2Function f2 = r2.getHashingFunction();
        if (f1.getAlgorithm().equals(f2.getAlgorithm()))
        {
            return Integer.compare(f2.getIterations(), f1.getIterations());
        }
        else
        {
            return Integer.compare(f2.getAlgorithm().getCode(), f1.getAlgorithm().getCode());
        }
    };


    public List<Result<PBKDF2Function>> testPBKDF2()
    {
        List<Result<PBKDF2Function>> result = new ArrayList<>();

        for (PBKDF2Function.Algorithm algorithm : PBKDF2Function.Algorithm.values())
        {
            for (int round : PBKDF2_ROUNDS)
            {
                PBKDF2Function pbkdf2Function = new PBKDF2Function(algorithm, round, algorithm.getBits());
                result.add(test(pbkdf2Function));
            }
        }
        result.sort(pbkdf2Comparator);
        return result;
    }


    protected <T extends HashingFunction> Result<T> test(T function)
    {
        long start = System.currentTimeMillis();

        for (int i = 0; i < LOOPS; i++)
        {
            function.hash(TO_BE_HASHED);
        }

        long end = System.currentTimeMillis();
        long duration = (end - start) / LOOPS;

        return new Result<>(function, duration);
    }

    public <T extends HashingFunction> T findBest(List<Result<T>> results, long maxTime)
    {
        int i = 0;
        for (; i < results.size(); i++)
        {
            if (results.get(i).time <= maxTime)
            {
                break;
            }
        }
        return results.get(i).getHashingFunction();
    }


    public static class Result<F extends HashingFunction>
    {
        private F hashingFunction;

        private long time;

        public Result(F hashingFunction, long time)
        {
            this.hashingFunction = hashingFunction;
            this.time = time;
        }

        public F getHashingFunction()
        {
            return hashingFunction;
        }

        public long getTime()
        {
            return time;
        }

        @Override
        public String toString()
        {
            return "Result{" +
                    "hashingFunction=" + hashingFunction +
                    ", time=" + time +
                    "ms}";
        }
    }


}
