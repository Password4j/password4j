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

import java.util.Random;

public abstract  class PasswordGenerator
{
    protected char[] symbols;

    char[] getSymbols()
    {
        return this.symbols;
    }

    public char pickNewChar()
    {
        return pickNewChar(this.symbols);
    }



    public char pickNewChar(char excluded)
    {
        char[] newSymbols = new char[symbols.length - 1];
        int j = 0;
        for (char symbol : symbols)
        {
            if (symbol != excluded)
            {
                newSymbols[j++] = symbol;
            }
        }
       return pickNewChar(newSymbols);
    }

    private char pickNewChar(char[] symbols)
    {
        Random random = AlgorithmFinder.getSecureRandom();
        return symbols[random.nextInt(symbols.length)];
    }


}
