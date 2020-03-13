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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

class PropertyReader
{

    static final Properties PROPERTIES;

    static
    {
        InputStream in = PropertyReader.class.getResourceAsStream("/psw4j.properties");
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

        PROPERTIES = props;
    }

    static int readInt(String key, int defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
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

    static String readString(String key, String defaultValue)
    {
        if (key == null)
        {
            throw new BadParametersException("Key cannot be null");
        }

        String value = readString(key);
        if (value == null)
        {
            return defaultValue;
        }
        return value;
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
        return PROPERTIES.getProperty(key);
    }

    private PropertyReader()
    {
        //
    }

}
