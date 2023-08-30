/*
 *  (C) Copyright 2023 Password4j (http://password4j.com/).
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

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class SymbolBasedRule implements Rule
{
    final char[] symbols;

    final int quantity;

    SymbolBasedRule(char[] symbols)
    {
        this(symbols, 1);
    }

    SymbolBasedRule(char[] symbols, int quantity)
    {
        this.symbols = symbols;
        this.quantity = quantity;
    }

    char[] generateMinimumChars()
    {
        SecureRandom random = AlgorithmFinder.getSecureRandom();
        char[] result = new char[quantity];
        for (int i = 0; i < quantity; i++)
        {
            result[i] = symbols[random.nextInt(symbols.length)];
        }
        return result;
    }

    char[] symbols()
    {
        return symbols;
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(Arrays.hashCode(symbols), quantity);
    }

    @Override
    public String toString()
    {
        return "sbr[s=" + new String(symbols) + ", q=" + quantity + "]";
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null || !this.getClass().equals(obj.getClass()))
        {
            return false;
        }

        SymbolBasedRule otherRule = (SymbolBasedRule) obj;
        return Arrays.equals(symbols, otherRule.symbols) //
                && quantity == otherRule.quantity;
    }
}