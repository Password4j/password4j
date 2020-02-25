package com.password4j;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;


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

        String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", PBKDF2Strategy.DEFAULT_ALGORITHM.name());
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", PBKDF2Strategy.DEFAULT_ITERATIONS);
        int length = PropertyReader.readInt("hash.pbkdf2.length", PBKDF2Strategy.DEFAULT_LENGTH);

        return new PBKDF2Strategy(algorithm, iterations, length);
    }


    public static BCryptStrategy getBCryptInstance()
    {
        int rounds = PropertyReader.readInt("hash.bcrypt.rounds", BCryptStrategy.DEFAULT_ROUNDS);
        return new BCryptStrategy(rounds);
    }

    public static SCryptStrategy getSCryptInstance()
    {
        int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", SCryptStrategy.DEFAULT_WORKFACTOR);
        int resources = PropertyReader.readInt("hash.scrypt.resources", SCryptStrategy.DEFAULT_RES);
        int parallelization = PropertyReader.readInt("hash.scrypt.parallelization", SCryptStrategy.DEFAULT_PARALLELIZATION);
        return new SCryptStrategy(workFactor, resources, parallelization);
    }


    private static boolean useStrongRandom()
    {
        return PropertyReader.readBoolean("global.random.strong", false);
    }
}
