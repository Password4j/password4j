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
import java.util.Set;


/**
 * This utility class finds algorithms with their configuration
 * based on the environment.
 * <p>
 * In this context, by environment is intended the set of
 * parameters set in the JVM and in the <i>psw4j.properties</i> file.
 *
 * @author David Bertoldi
 * @since 0.1.0
 */
public class AlgorithmFinder
{

    private static final Logger LOG = LoggerFactory.getLogger(AlgorithmFinder.class);

    /**
     * Singleton instance of {@link SecureRandom}.
     * <p>
     * By definition this instance does not need
     * to be re-instantiated in order to generate
     * non-deterministic output.
     *
     * @see #getSecureRandom()
     * @since 0.1.0
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
                /* Even if there's no strong instance, execution
                 * must continue with a less strong SecureRandom instance */
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

    /**
     * Retrieve a singleton instance of a thread-safe {@link SecureRandom} object.
     * If the environment allows it, a cryptographically strong random number generator (RNG)
     * is returned.
     * <p>
     * The usage of {@link SecureRandom#getInstanceStrong()} can be forced by
     * setting {@code global.random.strong} to {@code true} in the <i>psw4j.properties</i>.
     * Please be aware that this configuration may affect the system performance, while
     * ensuring an high level of randomness.
     * <p>
     * It is recommendable for Unix systems to set {@code securerandom.source} to
     * {@code file:/dev/urandom} in your <i>java.security</i> file.
     *
     * @return a thread-safe {@link SecureRandom} instance
     * @see SecureRandom#getInstanceStrong()
     * @since 0.1.0
     */
    public static SecureRandom getSecureRandom()
    {
        return SR_SOURCE;
    }

    /**
     * Creates a singleton instance of {@link PBKDF2Function}
     * with the configuration set in the <i>psw4j.properties</i> file.
     * <p>
     * If no <i>psw4j.properties</i> is found in the classpath or no
     * value is provided for a parameter, the
     * default configuration is used.
     * <table>
     *   <tr>
     *     <th>Parameter</th>
     *     <th>Property</th>
     *     <th>Default</th>
     *   </tr>
     *   <tr>
     *     <td>Algorithm</td>
     *     <td>hash.pbkdf2.algorithm</td>
     *     <td>PBKDF2WithHmacSHA512</td>
     *   </tr>
     *   <tr>
     *     <td># iterations</td>
     *     <td>hash.pbkdf2.iterations</td>
     *     <td>64000</td>
     *   </tr>
     *   <tr>
     *     <td>Key length</td>
     *     <td>hash.pbkdf2.length</td>
     *     <td>512</td>
     *   </tr>
     * </table>
     *
     * @return a {@link PBKDF2Function}
     * @since 0.1.0
     */
    public static PBKDF2Function getPBKDF2Instance()
    {
        Param params = internalGetProperties();
        return PBKDF2Function.getInstance(params.algorithm, params.iterations, params.length);
    }

    /**
     * Creates a singleton instance of {@link CompressedPBKDF2Function}
     * with the configuration set in the <i>psw4j.properties</i> file.
     * <p>
     * If no <i>psw4j.properties</i> is found in the classpath or no
     * value is provided for a parameter, the
     * default configuration is used.
     * <table>
     *   <tr>
     *     <th>Parameter</th>
     *     <th>Property</th>
     *     <th>Default</th>
     *   </tr>
     *   <tr>
     *     <td>Algorithm</td>
     *     <td>hash.pbkdf2.algorithm</td>
     *     <td>PBKDF2WithHmacSHA512</td>
     *   </tr>
     *   <tr>
     *     <td># iterations</td>
     *     <td>hash.pbkdf2.iterations</td>
     *     <td>64000</td>
     *   </tr>
     *   <tr>
     *     <td>Key length</td>
     *     <td>hash.pbkdf2.length</td>
     *     <td>512</td>
     *   </tr>
     * </table>
     *
     * @return a {@link CompressedPBKDF2Function}
     * @since 0.1.0
     */
    public static CompressedPBKDF2Function getCompressedPBKDF2Instance()
    {
        Param params = internalGetProperties();
        return CompressedPBKDF2Function.getInstance(params.algorithm, params.iterations, params.length);
    }

    private static Param internalGetProperties()
    {
        String algorithm = PropertyReader.readString("hash.pbkdf2.algorithm", Hmac.SHA512.name(), "PBKDF2 algorithm is not defined");
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", 64_000, "PBKDF2 #iterations are not defined");
        int length = PropertyReader.readInt("hash.pbkdf2.length", Hmac.SHA512.bits(), "PBKDF2 key length is not defined");
        return new Param(algorithm, iterations, length);
    }

    /**
     * Creates a singleton instance of {@link BCryptFunction}
     * with the configuration set in the <i>psw4j.properties</i> file.
     * <p>
     * If no <i>psw4j.properties</i> is found in the classpath or no
     * value is provided for a parameter, the
     * default configuration is used.
     * <table>
     *   <tr>
     *     <th>Parameter</th>
     *     <th>Property</th>
     *     <th>Default</th>
     *   </tr>
     *   <tr>
     *      *     <td>Logarithmic number of rounds</td>
     *      *     <td>hash.bcrypt.minor</td>
     *      *     <td>10</td>
     *      *   </tr>
     *   <tr>
     *     <td>Logarithmic number of rounds</td>
     *     <td>hash.bcrypt.rounds</td>
     *     <td>10</td>
     *   </tr>
     * </table>
     *
     * @return a {@link BCryptFunction}
     * @since 0.1.0
     */
    public static BCryptFunction getBCryptInstance()
    {
        char minor = PropertyReader.readChar("hash.bcrypt.minor", 'b', "BCrypt minor version is not defined");
        int rounds = PropertyReader.readInt("hash.bcrypt.rounds", 10, "BCrypt rounds are not defined");
        return BCryptFunction.getInstance(BCrypt.valueOf(minor), rounds);
    }

    /**
     * Creates a singleton instance of {@link SCryptFunction}
     * with the configuration set in the <i>psw4j.properties</i> file.
     * <p>
     * If no <i>psw4j.properties</i> is found in the classpath or no
     * value is provided for a parameter, the
     * default configuration is used.
     * <table>
     *   <tr>
     *     <th>Parameter</th>
     *     <th>Property</th>
     *     <th>Default</th>
     *   </tr>
     *   <tr>
     *     <td>Work Factor (N)</td>
     *     <td>hash.scrypt.workfactor</td>
     *     <td>32768</td>
     *   </tr>
     *   <tr>
     *     <td>Resources (r)</td>
     *     <td>hash.scrypt.resources</td>
     *     <td>8</td>
     *   </tr>
     *   <tr>
     *     <td>Parallelization (p)</td>
     *     <td>hash.scrypt.parallelization</td>
     *     <td>1</td>
     *   </tr>
     * </table>
     *
     * @return a {@link SCryptFunction}
     * @since 0.1.0
     */
    public static SCryptFunction getSCryptInstance()
    {
        int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", 32_768, "SCrypt work factor (N) is not defined");
        int resources = PropertyReader.readInt("hash.scrypt.resources", 8, "SCrypt resources (r) is not defined");
        int parallelization = PropertyReader.readInt("hash.scrypt.parallelization", 1, "SCrypt parallelization (p) is not defined");
        return SCryptFunction.getInstance(workFactor, resources, parallelization);
    }

    public static MessageDigestFunction getMessageDigestInstance()
    {
        String algorithm = PropertyReader.readString("hash.md.algorithm", "SHA-512", "Message Digest algorithm is not defined");
        String saltOption = PropertyReader.readString("hash.md.salt.option", "APPEND", "Salt option is not defined");
        try
        {
            return MessageDigestFunction.getInstance(algorithm, SaltOption.valueOf(saltOption.toUpperCase()));
        }
        catch (IllegalArgumentException iae)
        {
            LOG.warn("{} is not a valid option. Fallback to default.", saltOption);
            return MessageDigestFunction.getInstance(algorithm);
        }
    }

    /**
     * Finds the list of supported PBKDF2 algorithms by
     * the environment's {@link Provider}s.
     *
     * @return the list of supported PBKDF2 algorithms
     * @since 0.2.0
     */
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

    public static Set<String> getAllMessageDigests()
    {
        return Security.getAlgorithms("MessageDigest");
    }

    private static boolean useStrongRandom()
    {
        return PropertyReader.readBoolean("global.random.strong", false);
    }

    private static class Param
    {
        String algorithm;
        int iterations;
        int length;

        Param(String algorithm, int iterations, int length)
        {
            this.algorithm = algorithm;
            this.iterations = iterations;
            this.length = length;
        }
    }
}
