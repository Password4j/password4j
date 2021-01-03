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

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Properties;


public class PropertyReaderTest
{

    @After
    @Before
    public void setup()
    {
        Thread.currentThread().setContextClassLoader(ClassLoader.getSystemClassLoader());
        System.clearProperty("psw4j.configuration");
        PropertyReader.init();
    }

    @Test
    public void testInt()
    {
        // GIVEN
        String key = "test.int";

        // WHEN
        int ten = PropertyReader.readInt(key, -4, null);
        int minusNine = PropertyReader.readInt(key + "abc", -9, null);

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
        String testString = PropertyReader.readString(key, "default string", null);
        String defaultValue = PropertyReader.readString(key + "abc", "default string", null);

        // THEN
        Assert.assertEquals("This is a string", testString);
        Assert.assertEquals("default string", defaultValue);
    }

    @Test
    public void testChar()
    {
        // GIVEN
        String key = "test.char";

        // WHEN
        int backslash = PropertyReader.readChar(key, '/');
        int slash = PropertyReader.readChar(key + "abc", '/');
        int backslash2 = PropertyReader.readChar(key, '/', null);
        int slash2 = PropertyReader.readChar(key + "abc", '/', null);

        // THEN
        Assert.assertEquals('\\', backslash);
        Assert.assertEquals('/', slash);
        Assert.assertEquals('\\', backslash2);
        Assert.assertEquals('/', slash2);
    }

    @Test(expected = BadParametersException.class)
    public void testNull()
    {
       PropertyReader.readString(null, "null", null);
    }

    @Test
    public void testInitInvalidPath()
    {
        // GIVEN
        System.setProperty("psw4j.configuration", "/my/improbable/path/xyz.properties");

        // WHEN
        PropertyReader.init();

        // THEN
        Assert.assertTrue(PropertyReader.properties.isEmpty());
    }

    @Test
    public void testInitCustomPath() throws Exception
    {
        // GIVEN
        String path = new File(".").getCanonicalPath() + "/src/test/my/custom/path/to/some.properties";
        System.out.println(path);
        System.setProperty("psw4j.configuration", path);

        // WHEN
        PropertyReader.init();

        // THEN
        Assert.assertFalse(PropertyReader.properties.isEmpty());
        Assert.assertEquals("hello!!", PropertyReader.readString("check.this.out", "kappa", null));
    }

    @Test
    public void testNoThreadClassLoader() throws Exception
    {
        // GIVEN
        String path = new File(".").getCanonicalPath() + "/src/test/my/custom/path/to/some.properties";
        System.out.println(path);
        System.setProperty("psw4j.configuration", path);
        Thread.currentThread().setContextClassLoader(null);

        // WHEN
        PropertyReader.init();

        // THEN
        Assert.assertFalse(PropertyReader.properties.isEmpty());
        Assert.assertEquals("hello!!", PropertyReader.readString("check.this.out", "kappa", null));
    }

    @Test
    public void testResource1()
    {
        // GIVEN

        // WHEN
        InputStream in = PropertyReader.getResource("PropertyReader.class");
        // THEN
        Assert.assertNotNull(in);
    }

}
