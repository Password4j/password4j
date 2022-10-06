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

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class EntropyBasedGenerator
{
    private static final String LETTERS = "abcdefghijklmnopqrstuvwxyz";

    static final char[] LOWERCASE_LETTERS = LETTERS.toCharArray();

    static final char[] UPPERCASE_LETTERS = LETTERS.toUpperCase(Locale.ENGLISH).toCharArray();

    static final char[] DIGITS = "0123456789".toCharArray();

    static final char[] SPECIALS_CHARACTERS = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".toCharArray();

    private static final double LOG2 = Math.log10(2);

    private static final Map<String, EntropyBasedGenerator> INSTANCES = new ConcurrentHashMap<>();


    protected char[] symbols;

    private EntropyBasedGenerator(char[] symbols)
    {
        this.symbols = symbols;
    }

    public static EntropyBasedGenerator getInstance(char[] symbols)
    {
        String key = getUID(symbols);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            EntropyBasedGenerator generator = new EntropyBasedGenerator(symbols);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    public String generate()
    {
        return "asd";
    }


    double calculateEntropy(String testString)
    {
        int flag = 0;
        int poolSize = 0;
        for(char c : testString.toCharArray())
        {
            if((flag & 1) == 0 && Arrays.binarySearch(LOWERCASE_LETTERS, c) > -1)
            {
                poolSize += LOWERCASE_LETTERS.length;
                flag |= 1;

            }
            else if((flag & 2) == 0 && Arrays.binarySearch(UPPERCASE_LETTERS, c) > -1)
            {
                poolSize += UPPERCASE_LETTERS.length;
                flag |= 2;
            }
            else if((flag & 4) == 0 && Arrays.binarySearch(DIGITS, c) > -1)
            {
                poolSize += DIGITS.length;
                flag |= 4;
            }
            else if((flag & 8) == 0 && Arrays.binarySearch(SPECIALS_CHARACTERS, c) > -1)
            {
                poolSize += SPECIALS_CHARACTERS.length;
                flag |= 8;
            }
        }

        if (poolSize > 0)
        {
            return Math.log10(poolSize) * testString.length() / LOG2;
        }
        return 0d;
    }

    private static String getUID(char[] symbols)
    {
        return String.valueOf(symbols);
    }


}
