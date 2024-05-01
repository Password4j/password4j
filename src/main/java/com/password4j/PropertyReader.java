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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessControlException;
import java.util.Properties;


class PropertyReader
{

    private static final Logger LOG = LoggerFactory.getLogger(PropertyReader.class);

    private static final String FILE_NAME = "psw4j.properties";

    private static final String CONFIGURATION_KEY = "psw4j.configuration";

    private static final String MESSAGE = "{}. Default value is used ({}). Please set property {} in your " + FILE_NAME + " file.";

    protected static Properties properties;

    static
    {
        init();
    }

    private PropertyReader()
    {
        //
    }

    static int readInt(String key, int defaultValue, String message)
    {
        String str = readString(key);
        if (str == null)
        {
            LOG.warn(MESSAGE, message, defaultValue, key);
            return defaultValue;
        }
        return Integer.parseInt(str);
    }

    static boolean readBoolean(String key, boolean defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
            return defaultValue;
        }
        return Boolean.parseBoolean(str);
    }

    static String readString(String key, String defaultValue, String message)
    {
        String value = readString(key);
        if (value == null)
        {
            LOG.warn(MESSAGE, message, defaultValue, key);
            return defaultValue;
        }
        return value;
    }

    static char readChar(String key, char defaultValue, String message)
    {
        String str = readString(key);
        if (str == null)
        {
            LOG.warn(MESSAGE, message, defaultValue, key);
            return defaultValue;
        }
        return str.charAt(0);
    }

    static char readChar(String key, char defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
            return defaultValue;
        }
        return str.charAt(0);
    }

    private static String readString(String key)
    {
        if (key == null)
        {
            throw new BadParametersException("Key cannot be null");
        }

        if (properties != null)
        {
            return properties.getProperty(key);
        }
        return null;
    }

    static void init()
    {
        String customPath = null;

        try
        {
            customPath = System.getProperty(CONFIGURATION_KEY, null);
        }
        catch (AccessControlException ex)
        {
            LOG.debug("Cannot access configuration key property", ex);
        }

        InputStream in = null;
        Properties props = new Properties();
        try
        {
            if (customPath == null || customPath.isEmpty())
            {
                in = getResource('/' + FILE_NAME);
            }
            else
            {
                in = getResource(customPath);
            }
        }
        catch (AccessControlException ex)
        {
            LOG.debug("Cannot access properties file", ex);
            props.setProperty("global.banner", "false");
        }

        if (in != null)
        {
            try
            {
                props.load(in);
            }
            catch (IOException e)
            {
                //
            }
        }
        else
        {
            LOG.debug("Cannot find any properties file.");
        }

        properties = props;
    }

    static InputStream getResource(String resource)
    {
        ClassLoader classLoader;
        InputStream in;

        try
        {
            classLoader = Thread.currentThread().getContextClassLoader();
            if (classLoader != null)
            {
                in = classLoader.getResourceAsStream(resource);
                if (in != null)
                {
                    return in;
                }
            }

            // Try with the class loader that loaded this class
            classLoader = PropertyReader.class.getClassLoader();
            if (classLoader != null)
            {
                in = classLoader.getResourceAsStream(resource);
                if (in != null)
                {
                    return in;
                }
            }
        }
        catch (Exception e)
        {
            LOG.warn("", e);
        }

        // Get the resource from the class path in case that the class is loaded
        // by the Extension class loader which the parent of the system class loader.
        in = ClassLoader.getSystemResourceAsStream(resource);
        if (in != null)
        {
            return in;
        }

        try
        {
            return new FileInputStream(resource);
        }
        catch (FileNotFoundException e)
        {
            return PropertyReader.class.getResourceAsStream(resource);
        }

    }

}
