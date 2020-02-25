package com.password4j;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class AlgorithmFinder
{

    private static final Logger LOG = LogManager.getLogger();

    /**
     * Make sure to use /dev/urandom instead of /dev/random in your
     * `java.security` file.
     * <code>securerandom.source=file:/dev/urandom</code>
     */
    private static final SecureRandom SR_SOURCE;

    private static final String[] PBKDF2_VARIANTS;

    private static final HashingStrategy[] STRATS = new HashingStrategy[3];

    static
    {
        SecureRandom sr;
        if (useStrongRandom())
        {
            try
            {
                sr = SecureRandom.getInstanceStrong();
            }
            catch (NoSuchAlgorithmException nsae)
            {
                LOG.warn("No source of strong randomness found for this environment.");
                sr = new SecureRandom();
            }

        }
        else
        {
            sr = new SecureRandom();
        }
        SR_SOURCE = sr;

        List<String> result = new ArrayList<>();
        for (Provider provider : Security.getProviders())
        {
            for (Provider.Service service : provider.getServices())
            {
                if ("SecretKeyFactory".equals(service.getType()) && service.getAlgorithm().startsWith("PBKDF2"))
                {
                    result.add(service.getAlgorithm());
                }
            }
        }
        PBKDF2_VARIANTS = result.toArray(new String[0]);




    }

    private AlgorithmFinder()
    {
        //
    }

    public static SecureRandom getSecureRandom()
    {
        return SR_SOURCE;
    }

    public static String[] getPBKDF2Variants()
    {
        return PBKDF2_VARIANTS;
    }

    public static PBKDF2Strategy getPBKDF2Instance()
    {
        PBKDF2Strategy strategy;
        if(STRATS[1] == null)
        {
            String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", PBKDF2Strategy.DEFAULT_ALGORITHM.name());
            int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", PBKDF2Strategy.DEFAULT_ITERATIONS);
            int length = PropertyReader.readInt("hash.pbkdf2.length", PBKDF2Strategy.DEFAULT_LENGTH);

            strategy = new PBKDF2Strategy(algorithm, iterations, length);
            STRATS[2] = strategy;
        }
        else
        {
            strategy = (PBKDF2Strategy) STRATS[2];
        }
        return strategy;
    }



    public static BCryptStrategy getBCryptInstance()
    {
        BCryptStrategy strategy;
        if(STRATS[1] == null)
        {
            int rounds = PropertyReader.readInt("hash.bcrypt.rounds", BCryptStrategy.DEFAULT_ROUNDS);
            strategy = new BCryptStrategy(rounds);
            STRATS[1] = strategy;
        }
        else
        {
            strategy = (BCryptStrategy) STRATS[1];
        }
        return strategy;
    }

    public static SCryptStrategy getSCryptInstance()
    {
        SCryptStrategy strategy;
        if(STRATS[1] == null)
        {
            int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", SCryptStrategy.DEFAULT_WORKFACTOR);
            int resources = PropertyReader.readInt("hash.scrypt.resources", SCryptStrategy.DEFAULT_RES);
            int parallelization = PropertyReader.readInt("hash.scrypt.parallelization", SCryptStrategy.DEFAULT_PARALLELIZATION);
            strategy = new SCryptStrategy(workFactor, resources, parallelization);
            STRATS[2] = strategy;
        }
        else
        {
            strategy = (SCryptStrategy) STRATS[2];
        }
        return strategy;
    }


    private static boolean useStrongRandom()
    {
        return PropertyReader.readBoolean("global.random.strong", false);
    }
}
