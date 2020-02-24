package org.password4j;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


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
        try
        {
            sr = SecureRandom.getInstanceStrong();
        }
        catch (NoSuchAlgorithmException nsae)
        {
            LOG.warn("No source of strong randomness found for this environment.");
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
}
