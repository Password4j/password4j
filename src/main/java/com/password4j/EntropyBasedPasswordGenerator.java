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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EntropyBasedPasswordGenerator extends PasswordGenerator
{


    private static final double LOG2 = Math.log10(2);

    private static final Map<String, EntropyBasedPasswordGenerator> INSTANCES = new ConcurrentHashMap<>();


    protected double minimumEntropy;

    private EntropyBasedPasswordGenerator(double minimumEntropy, char[] symbols)
    {
        this.minimumEntropy = minimumEntropy;
        this.symbols = symbols;
    }

    public static EntropyBasedPasswordGenerator getInstance(double minimumEntropy, String symbols)
    {
        return getInstance(minimumEntropy, symbols.toCharArray());
    }

    public static EntropyBasedPasswordGenerator getInstance(double minimumEntropy, char[] symbols)
    {
        String key = getUID(minimumEntropy, symbols);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            EntropyBasedPasswordGenerator generator = new EntropyBasedPasswordGenerator(minimumEntropy, symbols);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    public String generate()
    {
        StringBuilder sb = new StringBuilder();

        do
        {
            sb.append(pickNewChar());

        } while (calculateEntropy(sb.toString()) < minimumEntropy);

        return sb.toString();
    }

    double calculateEntropy(String testString)
    {
        int flag = 0;
        int poolSize = 0;
        for(char c : testString.toCharArray())
        {
            if((flag & 1) == 0 && Arrays.binarySearch(Symbols.LOWERCASE_LETTERS_CHARS, c) > -1)
            {
                poolSize += Symbols.LOWERCASE_LETTERS_CHARS.length;
                flag |= 1;

            }
            else if((flag & 2) == 0 && Arrays.binarySearch(Symbols.UPPERCASE_LETTERS_CHARS, c) > -1)
            {
                poolSize += Symbols.UPPERCASE_LETTERS_CHARS.length;
                flag |= 2;
            }
            else if((flag & 4) == 0 && Arrays.binarySearch(Symbols.DIGITS_CHARS, c) > -1)
            {
                poolSize += Symbols.DIGITS_CHARS.length;
                flag |= 4;
            }
            else if((flag & 8) == 0 && Arrays.binarySearch(Symbols.SPECIALS_CHARACTERS_CHARS, c) > -1)
            {
                poolSize += Symbols.SPECIALS_CHARACTERS_CHARS.length;
                flag |= 8;
            }
        }

        if (poolSize > 0)
        {
            return Math.log10(poolSize) * testString.length() / LOG2;
        }
        return 0d;
    }


    private static String getUID(double minimumEntropy, char[] symbols)
    {
        StringBuilder sb = new StringBuilder(symbols.length + 1);
        sb.append(minimumEntropy);
        for (char c: symbols)
        {
            sb.append(c);
        }
        return sb.toString();
    }


}
