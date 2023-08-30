package com.password4j;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class RuleBasedPasswordGeneratorTest
{

    @Test
    public void testCustomRule()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("ab".toCharArray(), 30), Rule.specials};
        int length = 31;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, 'a', 'b'));
        Assert.assertTrue(contains(generated, 1, Symbols.SPECIALS_CHARACTERS_CHARS));
    }


    @Test
    public void testMoreThanOne()
    {
        // GIVEN
        Rule[] rules = new Rule[]{Rule.lowerCaseLetters, Rule.specials, Rule.digits};
        int length = 4;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, 1, Symbols.LOWERCASE_LETTERS_CHARS));
        Assert.assertTrue(contains(generated, 1, Symbols.SPECIALS_CHARACTERS_CHARS));
        Assert.assertTrue(contains(generated, 1, Symbols.DIGITS_CHARS));
        Assert.assertTrue(contains(generated, length, Utils.append(Utils.append(Symbols.LOWERCASE_LETTERS_CHARS, Symbols.SPECIALS_CHARACTERS_CHARS), Symbols.DIGITS_CHARS)));
    }


    @Test
    public void testMoreThanX()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("XYZ".toCharArray(), 5), Rule.digits, new SymbolBasedRule("ZAB".toCharArray(), 2)};
        int length = 10;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, 5, 'X', 'Y', 'Z'));
        Assert.assertTrue(contains(generated, 1, Symbols.DIGITS_CHARS));
        Assert.assertTrue(contains(generated, 2, 'Z', 'A', 'B'));
    }

    @Test
    public void testOnlyOne()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("1".toCharArray(), 1)};
        int length = 44;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, 1, '1'));
        Assert.assertTrue(contains(generated, length, '1'));
    }

    @Test
    public void noLength()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("empty".toCharArray(), 0)};
        int length = 0;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertEquals("", generated);
    }

    @Test(expected = BadParametersException.class)
    public void notEnough()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("1".toCharArray(), 10), new SymbolBasedRule("1".toCharArray(), 5)};
        int length = 14;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN

    }

    private static boolean contains(String generated, char... symbols)
    {
        for (char c : symbols)
        {
            if (generated.indexOf(c) >= 0)
            {
                return true;
            }
        }
        return false;
    }

    private static boolean contains(String generated, int count, char... symbols)
    {
        int r = 0;
        for (char c : symbols)
        {
            for (int i = 0; i < generated.length(); i++)
            {
                if (generated.charAt(i) == c)
                {
                    r++;
                }
            }

        }
        return r >= count;
    }

}
