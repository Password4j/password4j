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

import org.junit.Assert;
import org.junit.Test;


public class PropertyReaderTest
{
    @Test
    public void testInt()
    {
        // GIVEN
        String key = "test.int";

        // WHEN
        int ten = PropertyReader.readInt(key, -4);
        int minusNine = PropertyReader.readInt(key + "abc", -9);

        // THEN
        Assert.assertEquals(10, ten);
        Assert.assertEquals(-9, minusNine);
    }

    @Test
    public void testBool()
    {
        // GIVEN
        String key = "test.bool";

        // WHEN
        boolean bool1 = PropertyReader.readBoolean(key, false);
        boolean bool2 = PropertyReader.readBoolean(key + "abc", true);

        // THEN
        Assert.assertTrue(bool1);
        Assert.assertTrue(bool2);
    }

    @Test
    public void testString()
    {
        // GIVEN
        String key = "test.string";

        // WHEN
        String testString = PropertyReader.readString(key, "default string");
        String defaultValue = PropertyReader.readString(key + "abc", "default string");

        // THEN
        Assert.assertEquals("This is a string", testString);
        Assert.assertEquals("default string", defaultValue);
    }

    @Test(expected = BadParametersException.class)
    public void testNull()
    {
        // GIVEN
        String key = "test.string";

        // WHEN
        String testString = PropertyReader.readString(null, "null");
    }
}
