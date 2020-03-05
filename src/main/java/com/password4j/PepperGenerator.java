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

import org.apache.commons.lang3.RandomStringUtils;


public class PepperGenerator
{

    private PepperGenerator()
    {
        //
    }

    public static String generate(int length)
    {
        if(length < 0)
        {
            throw new BadParametersException("Pepper length cannot be negative");
        }
        return RandomStringUtils.random(length, 32, 126, false, false, null, AlgorithmFinder.getSecureRandom());
    }

    public static String generate()
    {
        return generate(24);
    }

    public static String get()
    {
        return PropertyReader.readString("global.pepper", null);
    }

}
