package com.password4j;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

class PropertyReader
{

    private static final Properties PROPERTIES;

    static
    {
        InputStream in = PropertyReader.class.getResourceAsStream("/psw4j.properties");
        Properties props = new Properties();

        try
        {
            props.load(in);
        }
        catch (IOException e)
        {
            //
        }

        PROPERTIES = props;
    }

    public static int readInt(String key, int defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
            return defaultValue;
        }
        return Integer.parseInt(readString(key));
    }

    public static boolean readBoolean(String key, boolean defaultValue)
    {
        String str = readString(key);
        if (str == null)
        {
            return defaultValue;
        }
        return Boolean.parseBoolean(readString(key));
    }

    private static String readString(String key)
    {
        return PROPERTIES.getProperty(key);
    }

    public static String readString(String key, String defaultValue)
    {
        String value = PROPERTIES.getProperty(key);
        if (value == null)
        {
            return defaultValue;
        }
        return value;
    }

    private PropertyReader()
    {
        //
    }

}
