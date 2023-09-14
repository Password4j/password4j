/*
 *  (C) Copyright 2022 Password4j (http://password4j.com/).
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

import com.password4j.types.Hmac;

import java.time.Duration;

public class GeneratorBuilder
{

    private PasswordGenerator passwordGenerator;

    private int length = 8;

    public String _new(PasswordGenerator passwordGenerator)

    public GeneratorBuilder newTOTP(Hmac hmac, Duration duration)
    {
        passwordGenerator = TOTPGenerator.getInstance(hmac, duration, length);
        return this;
    }


    public GeneratorBuilder newHOTP()
    {
        passwordGenerator = HOTPGenerator.getInstance(length);
        return this;
    }


    public GeneratorBuilder newPassword(double minimumEntropy, String symbols)
    {
        passwordGenerator = EntropyBasedPasswordGenerator.getInstance(minimumEntropy, symbols);
        return this;
    }

    public GeneratorBuilder newPassword(double minimumEntropy, char[] symbols)
    {
        passwordGenerator = EntropyBasedPasswordGenerator.getInstance(minimumEntropy, symbols);
        return this;
    }

    public GeneratorBuilder newPassword(Rule... rules)
    {
        passwordGenerator = RuleBasedPasswordGenerator.getInstance(length, rules);
        return this;
    }


    public GeneratorBuilder withLength(int length)
    {
        this.length = length;
        return this;
    }

}
