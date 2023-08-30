package com.password4j;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RuleBasedPasswordGenerator extends PasswordGenerator
{
    private static final Map<String, RuleBasedPasswordGenerator> INSTANCES = new ConcurrentHashMap<>();

    private final int length;

    private final Rule[] rules;

    private RuleBasedPasswordGenerator(int length, Rule... rules)
    {
        this.length = length;
        this.rules = rules;
    }


    public static RuleBasedPasswordGenerator getInstance(int length, Rule... rules)
    {
        String key = getUID(length, rules);
        if (INSTANCES.containsKey(key))
        {
            return INSTANCES.get(key);
        }
        else
        {
            RuleBasedPasswordGenerator generator = new RuleBasedPasswordGenerator(length, rules);
            INSTANCES.put(key, generator);
            return generator;
        }
    }

    public String generate()
    {
        int minimumLength = 0;
        char[] symbols = new char[0];

        for (Rule rule : rules)
        {
            if (rule instanceof SymbolBasedRule)
            {
                SymbolBasedRule symbolBasedRule = (SymbolBasedRule) rule;
                minimumLength += symbolBasedRule.quantity;
                symbols = Utils.append(symbols, symbolBasedRule.symbols);
            }
        }

        if (minimumLength > length)
        {
            throw new BadParametersException("Insufficient length: with the current rules needed " + minimumLength + " but got " + length);
        }

        SecureRandom secureRandom = AlgorithmFinder.getSecureRandom();
        StringBuilder sb = new StringBuilder();

        for (Rule rule : rules)
        {
            if (rule instanceof SymbolBasedRule)
            {
                SymbolBasedRule symbolBasedRule = (SymbolBasedRule) rule;
                sb.append(symbolBasedRule.generateMinimumChars());
            }
        }

        if (length > minimumLength)
        {
            int uncovered = length - minimumLength;

            for (int i = 0; i < uncovered; i++)
            {
                sb.append(symbols[secureRandom.nextInt(symbols.length)]);
            }
        }

        return shuffle(sb.toString());
    }

    private String shuffle(String generated)
    {
        List<Character> list = new ArrayList<>();
        for(char c :  generated.toCharArray())
        {
            list.add(c);
        }

        Collections.shuffle(list, AlgorithmFinder.getSecureRandom());

        StringBuilder sb = new StringBuilder();
        for(char c : list)
        {
            sb.append(c);
        }

        return sb.toString();
    }

    private static String getUID(int length, Rule... rules)
    {
        StringBuilder sb = new StringBuilder(rules.length + 1);
        sb.append(length);
        for (Rule rule: rules)
        {
            sb.append(rule.toString());
        }
        return sb.toString();
    }
}
