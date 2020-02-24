package com.password4j;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PropertyReader
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

    public static int readInt(String key)
    {
        String str = readString(key);
        if(str == null)
        {
            return 0;
        }
        return Integer.parseInt(readString(key));
    }

    public static boolean readBoolean(String key)
    {
        String str = readString(key);
        if(str == null)
        {
            return false;
        }
        return Boolean.parseBoolean(readString(key));
    }

    public static String readString(String key)
    {
        return PROPERTIES.getProperty(key);
    }

}
