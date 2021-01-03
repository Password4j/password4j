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

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

class PropertyReader
{

    private static final Logger LOG = LoggerFactory.getLogger(PropertyReader.class);

    private static final String FILE_NAME = "/psw4j.properties";

    private static final String CONFIGURATION_KEY = "psw4j.configuration";

    private static final String MESSAGE = "{}. Default value is used ({}). Please set property {} in your " + FILE_NAME + " file.";


    protected static  Properties properties;

    static
    {
        init();
    }

    static int readInt(String key, int defaultValue, String message)
    {
        String str = readString(key);
        if (str == null)
        {
            LOG.warn(MESSAGE, message, defaultValue, key);
            return defaultValue;
        }
        return Integer.parseInt(readString(key));
    }


    static boolean readBoolean(String key, boolean defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
            return defaultValue;
        }
        return Boolean.parseBoolean(readString(key));
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
        return properties.getProperty(key);
    }

    static void init()
    {
        String customPath = System.getProperty(CONFIGURATION_KEY, null);

        InputStream in;
        if (StringUtils.isEmpty(customPath))
        {
            in = getResource(FILE_NAME);
        }
        else
        {
            in = getResource(customPath);
        }

        Properties props = new Properties();


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

        properties =  props;
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
            LOG.warn("",e);
        }

        // Get the resource from the class path in case that the class is loaded
        // by the Extension class loader which the parent of the system class loader.
        in =  ClassLoader.getSystemResourceAsStream(resource);
        if(in != null)
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


    private PropertyReader()
    {
        //
    }

}
