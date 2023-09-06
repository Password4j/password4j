package com.password4j;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class EntropyBasedPasswordGeneratorTest
{

    @Test
    public void testEquality()
    {
        // GIVEN
        EntropyBasedPasswordGenerator strategy1 = EntropyBasedPasswordGenerator.getInstance(34, Symbols.SPECIALS_CHARACTERS + Symbols.ALPHANUMERIC);
        EntropyBasedPasswordGenerator strategy2 = EntropyBasedPasswordGenerator.getInstance(34, Utils.append(Symbols.SPECIALS_CHARACTERS_CHARS, Symbols.ALPHANUMERIC.toCharArray()));
        EntropyBasedPasswordGenerator strategy3 = EntropyBasedPasswordGenerator.getInstance(33, Symbols.SPECIALS_CHARACTERS + Symbols.ALPHANUMERIC);
        EntropyBasedPasswordGenerator strategy4 = EntropyBasedPasswordGenerator.getInstance(23, Symbols.PRINTABLE + Symbols.DIGITS);
        EntropyBasedPasswordGenerator strategy5 = EntropyBasedPasswordGenerator.getInstance(23, Symbols.LETTERS + Symbols.DIGITS);


        // WHEN
        Map<EntropyBasedPasswordGenerator, String> map = new HashMap<>();
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
    public void testSingleCharsets()
    {

        String[] symbols = new String[] {Symbols.LOWERCASE_LETTERS, Symbols.UPPERCASE_LETTERS, Symbols.DIGITS, Symbols.SPECIALS_CHARACTERS};
        for (String charset : symbols)
        {
            for (int entropy = 1; entropy <= 128; entropy++)
            {
                EntropyBasedPasswordGenerator generator = EntropyBasedPasswordGenerator.getInstance(entropy, charset);

                String generated = generator.generate();

                Assert.assertTrue(generator.calculateEntropy(generated) >= entropy);
            }
        }


    }

    @Test
    public void testMixedCharsets()
    {

        String[] symbols = new String[] {Symbols.LOWERCASE_LETTERS, Symbols.UPPERCASE_LETTERS, Symbols.DIGITS, Symbols.SPECIALS_CHARACTERS};
        String finalCharset = "";
        for (String charset : symbols)
        {
            finalCharset += charset;
            for (int entropy = 1; entropy <= 128; entropy++)
            {
                EntropyBasedPasswordGenerator generator = EntropyBasedPasswordGenerator.getInstance(entropy, finalCharset);

                String generated = generator.generate();
                Assert.assertTrue(generator.calculateEntropy(generated) >= entropy);
            }
        }


    }

}
