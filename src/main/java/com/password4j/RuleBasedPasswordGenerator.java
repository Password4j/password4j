package com.password4j;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RuleBasedPasswordGenerator
{
    private static final Map<String, RuleBasedPasswordGenerator> INSTANCES = new ConcurrentHashMap<>();

    protected char[] symbols;

    private RuleBasedPasswordGenerator(char[] symbols)
    {
        this.symbols = symbols;
    }

    public static RuleBasedPasswordGenerator getInstance(char[] symbols)
    {
        String key = getUID(symbols);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            RuleBasedPasswordGenerator generator = new RuleBasedPasswordGenerator(symbols);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    public String generate()
    {
        return "";
    }

    private static String getUID(char[] symbols)
    {
        return String.valueOf(symbols);
    }
}
