package com.password4j;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class RuleBasedPasswordGeneratorTest
{


    @Test
    public void testEquality()
    {
        // GIVEN
        RuleBasedPasswordGenerator strategy1 = RuleBasedPasswordGenerator.getInstance(34, Rule.specials, Rule.alphanumeric);
        RuleBasedPasswordGenerator strategy2 = RuleBasedPasswordGenerator.getInstance(34, Rule.specials, Rule.alphanumeric);
        RuleBasedPasswordGenerator strategy3 = RuleBasedPasswordGenerator.getInstance(33, Rule.specials, Rule.alphanumeric);
        RuleBasedPasswordGenerator strategy4 = RuleBasedPasswordGenerator.getInstance(23, Rule.printable, Rule.digits);
        RuleBasedPasswordGenerator strategy5 = RuleBasedPasswordGenerator.getInstance(23, Rule.letters, Rule.digits);


        // WHEN
        Map<RuleBasedPasswordGenerator, String> map = new HashMap<>();
        map.put(strategy1, strategy1.toString());
        map.put(strategy2, strategy2.toString());
        map.put(strategy3, strategy3.toString());
        map.put(strategy4, strategy4.toString());
        map.put(strategy5, strategy5.toString());


        // THEN
        assertEquals(4, map.size());
        assertEquals(strategy1, strategy2);
    }


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

    @Test
    public void testNoRep()
    {
        // GIVEN
        Rule[] rules = new Rule[]{new SymbolBasedRule("ab".toCharArray(), 15),  Rule.noRepetitions};
        int length = 20;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, 'a', 'b'));
        Assert.assertTrue(generated.equals("babababababababababa") || generated.equals("abababababababababab"));
    }

    @Test
    public void testNoCons()
    {
        // GIVEN
        Rule[] rules = new Rule[]{Rule.digits,  Rule.noConsecutives};
        int length = 1000;

        // WHEN
        RuleBasedPasswordGenerator generator = RuleBasedPasswordGenerator.getInstance(length, rules);
        String generated = generator.generate();

        // THEN
        Assert.assertEquals(length, generated.length());
        Assert.assertTrue(contains(generated, "0123456789".toCharArray()));
        Assert.assertFalse(consecutive(generated));
        System.out.println(generated);

    }

    private static boolean consecutive(String generated)
    {
        String[] checks = new String[]{"01", "12", "23", "34", "45", "56", "67", "78", "89", //
                                        "10", "21", "32", "43", "54", "65", "76", "87", "98" };

        for (String check : checks)
        {
            if (generated.contains(check))
            {
                return true;
            }
        }
        return false;
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
