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
import java.security.SecureRandom;


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
        String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", PBKDF2Function.DEFAULT_ALGORITHM.name());
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", PBKDF2Function.DEFAULT_ITERATIONS);
        int length = PropertyReader.readInt("hash.pbkdf2.length", PBKDF2Function.DEFAULT_LENGTH);

        return new PBKDF2Function(algorithm, iterations, length);
    }

    public static CompressedPBKDF2Function getCompressedPBKDF2Instance()
    {
        String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", PBKDF2Function.DEFAULT_ALGORITHM.name());
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", PBKDF2Function.DEFAULT_ITERATIONS);
        int length = PropertyReader.readInt("hash.pbkdf2.length", PBKDF2Function.DEFAULT_LENGTH);

        return new CompressedPBKDF2Function(algorithm, iterations, length);
    }


    public static BCryptFunction getBCryptInstance()
    {
        int rounds = PropertyReader.readInt("hash.bcrypt.rounds", BCryptFunction.DEFAULT_ROUNDS);
        return new BCryptFunction(rounds);
    }

    public static SCryptFunction getSCryptInstance()
    {
        int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", SCryptFunction.DEFAULT_WORKFACTOR);
        int resources = PropertyReader.readInt("hash.scrypt.resources", SCryptFunction.DEFAULT_RES);
        int parallelization = PropertyReader.readInt("hash.scrypt.parallelization", SCryptFunction.DEFAULT_PARALLELIZATION);
        return new SCryptFunction(workFactor, resources, parallelization);
    }


    private static boolean useStrongRandom()
    {
        return PropertyReader.readBoolean("global.random.strong", false);
    }
}
