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

import java.util.function.BiFunction;
import java.util.function.Function;


public class Password
{

    private Password()
    {
        //
    }


    public static HashBuilder hash(String plain)
    {
        return hash(plain, HashBuilder::new);
    }

    public static HashChecker check(String hash, String plain)
    {
        return check(hash, plain, HashChecker::new);
    }


    public static <B extends HashBuilder<?>> B hash(String plain, Function<String, B> builderFunction)
    {
        if (builderFunction == null)
        {
            throw new BadParametersException("HashBuilder construction method cannot be null");
        }
        if (plain == null)
        {
            throw new BadParametersException("Password cannot be null");
        }
        return builderFunction.apply(plain);
    }


    public static <C extends HashChecker<?>> C check(String hash, String plain, BiFunction<String, String, C> checkerBiFunction)
    {
        if (checkerBiFunction == null)
        {
            throw new BadParametersException("HashChecker construction method cannot be null");
        }
        if (hash == null || plain == null)
        {
            throw new BadParametersException("Hash or plain cannot be null");
        }
        return checkerBiFunction.apply(hash, plain);
    }


}
