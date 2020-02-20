package org.password4j.benchmark;

import java.util.List;

import org.password4j.AlgorithmFinder;
import org.password4j.encryption.EncryptionStrategy;
import org.password4j.encryption.PBKDF2Strategy;


public class BenchmarkEnvironment
{

    private static final char[] SHORT = "My$horTP4sS\\/\\/0rd".toCharArray();

    private static final long WARMUP_ROUNDS = 20;

    private static final long TEST_ROUNDS = WARMUP_ROUNDS * 1;

    private static final int[] ROUNDS = { 10_000, 32_000, 64_000};

    private static final int[] LENGTHS = { 256, 512, 1024 };

    private static final List<String> VARIANTS = AlgorithmFinder.getPBKDF2Variants();

    protected static void bench()
    {

        
        for (String v : VARIANTS)
        {
            for (int l : LENGTHS)
            {
                for (int r : ROUNDS)
                {
                    BenchmarkResult result = benchmarkEncryptionStrategy(new PBKDF2Strategy(v, r, l));
                    double millisSpent = ((double)result.getTiming()) / (result.getRounds());
                    System.out.println(v + " - [x" + r + " " + l + "bits] --> " + millisSpent);
                }
            }
        }

    }

    private static BenchmarkResult benchmarkEncryptionStrategy(EncryptionStrategy strategy)
    {
        BenchmarkResult result = new BenchmarkResult();

        for (long w = 0; w < WARMUP_ROUNDS; w++)
        {
            strategy.encrypt(SHORT);
        }

        long defaultStart = System.currentTimeMillis();

        for (long r = 0; r < TEST_ROUNDS; r++)
        {
            strategy.encrypt(SHORT);
        }

        long defaultEnd = System.currentTimeMillis();

        result.setRounds(TEST_ROUNDS);
        result.setTiming(defaultEnd - defaultStart);

        System.gc();

        return result;
    }

}
