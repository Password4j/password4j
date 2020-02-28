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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Assert;
import org.junit.Test;


public class BCryptStrategyTest
{

    @Test(expected = BadParametersException.class)
    public void testBCryptBadParams()
    {
        // GIVEN
        HashingFunction strategy = new BCryptFunction(-1);
        String password = "password";

        // WHEN
        strategy.hash(password);

        // THEN
    }

    @Test
    public void testBCryptCoherence()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new BCryptFunction().hash(password);

        // THEN
        Assert.assertTrue(hash.check(password));

    }

    @Test
    public void testBCryptCheckWithFixedConfigurations()
    {
        // GIVEN
        String password = "password";

        // WHEN
        Hash hash = new BCryptFunction(12).hash(password);

        // THEN
        Assert.assertTrue(hash.check(password));
    }

    @Test
    public void testBCryptequality()
    {
        // GIVEN
        BCryptFunction strategy1 = new BCryptFunction();
        BCryptFunction strategy2 = new BCryptFunction();
        BCryptFunction strategy3 = new BCryptFunction(15);
        BCryptFunction strategy4 = new BCryptFunction(15);
        BCryptFunction strategy5 = new BCryptFunction(8);

        // WHEN
        Map<BCryptFunction, String> map = new HashMap<>();
        map.put(strategy1, strategy1.toString());
        map.put(strategy2, strategy2.toString());
        map.put(strategy3, strategy3.toString());
        map.put(strategy4, strategy4.toString());
        map.put(strategy5, strategy5.toString());

        // THEN
        Assert.assertEquals(3, map.size());
        Assert.assertEquals(strategy1, strategy2);
        Assert.assertEquals(strategy3, strategy4);
    }

    @Test
    public void testLongPassword()
    {
        // GIVEN
        String password1 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor";
        String password2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod 7€Mp0R";
        String salt = "$2a$10$bJ2SJm8Xyp8H9KLeyNE5EO";

        // WHEN
        Hash hash1 = new BCryptFunction().hash(password1, salt);
        Hash hash2 = new BCryptFunction().hash(password2, salt);

        // THEN
        Assert.assertEquals(hash1, hash2);

    }
}
