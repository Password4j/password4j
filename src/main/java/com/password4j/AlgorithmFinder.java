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
    private static SecureRandom secureRandom;

    static
    {
        initialize();
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
        return secureRandom;
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
     *     <td>PBKDF2WithHmacSHA256</td>
     *   </tr>
     *   <tr>
     *     <td># iterations</td>
     *     <td>hash.pbkdf2.iterations</td>
     *     <td>310000</td>
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
        String algorithm = PropertyReader
                .readString("hash.pbkdf2.algorithm", Hmac.SHA256.name(), "PBKDF2 algorithm is not defined");
        int iterations = PropertyReader.readInt("hash.pbkdf2.iterations", 310_000, "PBKDF2 #iterations are not defined");
        int length = PropertyReader.readInt("hash.pbkdf2.length", Hmac.SHA256.bits(), "PBKDF2 key length is not defined");
        return new Param(algorithm, iterations, length);
    }

    /**
     * Creates a singleton instance of {@link BcryptFunction}
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
     * @return a {@link BcryptFunction}
     * @since 0.1.0
     */
    public static BcryptFunction getBcryptInstance()
    {
        char minor = PropertyReader.readChar("hash.bcrypt.minor", 'b', "bcrypt minor version is not defined");
        int rounds = PropertyReader.readInt("hash.bcrypt.rounds", 10, "bcrypt rounds are not defined");
        return BcryptFunction.getInstance(Bcrypt.valueOf(minor), rounds);
    }

    /**
     * Creates a singleton instance of {@link ScryptFunction}
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
     *     <td>65536</td>
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
     *   <tr>
     *     <td>Derived Key Length (dkLen)</td>
     *     <td>hash.scrypt.derivedKeyLength</td>
     *     <td>64</td>
     *   </tr>
     * </table>
     *
     * @return a {@link ScryptFunction}
     * @since 0.1.0
     */
    public static ScryptFunction getScryptInstance()
    {
        int workFactor = PropertyReader.readInt("hash.scrypt.workfactor", 65_536, "scrypt work factor (N) is not defined");
        int resources = PropertyReader.readInt("hash.scrypt.resources", 8, "scrypt resources (r) is not defined");
        int parallelization = PropertyReader
                .readInt("hash.scrypt.parallelization", 1, "scrypt parallelization (p) is not defined");
        int derivedKeyLength = PropertyReader.readInt("hash.scrypt.derivedKeyLength", ScryptFunction.DERIVED_KEY_LENGTH,
                "scrypt derivedKeyLength (dkLen) is not defined");
        return ScryptFunction.getInstance(workFactor, resources, parallelization, derivedKeyLength);
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
     * Creates a singleton instance of {@link Argon2Function}
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
     *     <td>Memory (log2)</td>
     *     <td>hash.argon2.memory</td>
     *     <td>15</td>
     *   </tr>
     *   <tr>
     *     <td>Iterations</td>
     *     <td>hash.argon2.iterations</td>
     *     <td>2</td>
     *   </tr>
     *   <tr>
     *     <td>Output Length</td>
     *     <td>hash.argon2.length</td>
     *     <td>32</td>
     *   </tr>
     *   <tr>
     *     <td>Parallelism</td>
     *     <td>hash.argon2.parallelism</td>
     *     <td>1</td>
     *   </tr>
     *   <tr>
     *     <td>Type</td>
     *     <td>hash.argon2.type</td>
     *     <td>id</td>
     *   </tr>
     *   <tr>
     *     <td>Version</td>
     *     <td>hash.argon2.version</td>
     *     <td>19</td>
     *   </tr>
     * </table>
     *
     * @return a {@link ScryptFunction}
     * @since 1.5.0
     */
    public static Argon2Function getArgon2Instance()
    {
        int memory = PropertyReader.readInt("hash.argon2.memory", 15_360, "Argon2 memory is not defined");
        int iterations = PropertyReader.readInt("hash.argon2.iterations", 2, "Argon2 #iterations is not defined");
        int outputLength = PropertyReader.readInt("hash.argon2.length", 32, "Argon2 output length is not defined");
        int parallelism = PropertyReader.readInt("hash.argon2.parallelism", 1, "Argon2 parallelism is not defined");
        String type = PropertyReader.readString("hash.argon2.type", "id", "Argon2 type is not defined");
        int version = PropertyReader.readInt("hash.argon2.version", 19, "Argon2 version is not defined");
        return Argon2Function
                .getInstance(memory, iterations, parallelism, outputLength, Argon2.valueOf(type.toUpperCase()), version);
    }

    public static BalloonHashingFunction getBalloonHashingInstance()
    {
        int space = PropertyReader.readInt("hash.balloon.space", 1024, "BalloonHashing memory (space) is not defined");
        int time = PropertyReader.readInt("hash.balloon.time", 3, "BalloonHashing #iterations (time) is not defined");
        int parallelism = PropertyReader.readInt("hash.balloon.parallelism", 1, "BalloonHashing parallelism is not defined");
        int delta = PropertyReader.readInt("hash.balloon.delta", 3, "BalloonHashing delta is not defined");
        String algorithm = PropertyReader.readString("hash.balloon.algorithm", "SHA-256", "BalloonHashing algorithm is not defined");
        return BalloonHashingFunction.getInstance(algorithm, space, time, parallelism, delta);
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
            // Some JDK implementation may return null instead of an empty array.
            // see https://github.com/Password4j/password4j/issues/120
            if (provider.getServices() != null)
            {
                for (Provider.Service service : provider.getServices())
                {
                    if ("SecretKeyFactory".equals(service.getType()) && service.getAlgorithm().startsWith("PBKDF2"))
                    {
                        result.add(service.getAlgorithm());
                    }
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

    static void initialize()
    {
        SecureRandom sr;
        if (useStrongRandom())
        {
            try
            {
                sr = Utils.getInstanceStrong();
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
        secureRandom = sr;
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
