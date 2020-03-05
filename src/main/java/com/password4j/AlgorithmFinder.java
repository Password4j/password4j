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


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;


public class AlgorithmFinder
{

    private static final Logger LOG = LoggerFactory.getLogger(AlgorithmFinder.class);

    /**
     * Make sure to use /dev/urandom instead of /dev/random in your
     * `java.security` file.
     * <code>securerandom.source=file:/dev/urandom</code>
     */
    private static final SecureRandom SR_SOURCE;

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

    }

    private AlgorithmFinder()
    {
        //
    }

    public static SecureRandom getSecureRandom()
    {
        return SR_SOURCE;
    }

    public static PBKDF2Function getPBKDF2Instance()
    {
        return getPBKDF2Instance(a -> (i -> l -> (PBKDF2Function.getInstance(a, i, l))));
    }

    public static CompressedPBKDF2Function getCompressedPBKDF2Instance()
    {
        return getPBKDF2Instance(a -> (i -> l -> (CompressedPBKDF2Function.getInstance(a, i, l))));
    }

    private static <T extends PBKDF2Function> T getPBKDF2Instance(Function<String, Function<Integer, Function<Integer, T>>> f)
    {
        String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", PBKDF2Function.Algorithm.PBKDF2WithHmacSHA512.name());
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", 64_000);
        int length = PropertyReader.readInt("hash.pbkdf2.length", PBKDF2Function.Algorithm.PBKDF2WithHmacSHA512.bits());
        return f.apply(algorithm).apply(iterations).apply(length);
    }


    public static BCryptFunction getBCryptInstance()
    {
        int rounds = PropertyReader.readInt("hash.bcrypt.rounds", 10);
        return BCryptFunction.getInstance(rounds);
    }

    public static SCryptFunction getSCryptInstance()
    {
        int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", 32_768);
        int resources = PropertyReader.readInt("hash.scrypt.resources", 8);
        int parallelization = PropertyReader.readInt("hash.scrypt.parallelization", 1);
        return SCryptFunction.getInstance(workFactor, resources, parallelization);
    }

    public static List<String> getAllPBKDF2Variants()
    {
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
        return result;
    }


    private static boolean useStrongRandom()
    {
        return PropertyReader.readBoolean("global.random.strong", false);
    }
}
