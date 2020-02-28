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

package com.password4j.custom;

import com.password4j.Hash;
import com.password4j.HashBuilder;

public class CustomHashBuilder extends HashBuilder<CustomHashBuilder>
{

    public static final String SAME_RESULT = "i always produce this hash";

    public CustomHashBuilder(String plain)
    {
        super(plain);
    }

    public Hash withTest()
    {
        return new Hash(null, SAME_RESULT, null);
    }

    @Override
    public Hash withBCrypt()
    {
        return new Hash(null, SAME_RESULT, null);
    }
}
