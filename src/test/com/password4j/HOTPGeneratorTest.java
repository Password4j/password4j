package com.password4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.time.Duration;

import com.password4j.types.Hmac;
import org.junit.Assert;
import org.junit.Test;



public class HOTPGeneratorTest
{

    private static final byte[] TEST_SECRET = "12345678901234567890".getBytes(StandardCharsets.UTF_8);

    private static final String[][] TEST_VECTOR_N = {
            { "4", "2", "2", "9", "4", "6", "2", "3", "1", "9" },
            { "24", "82", "52", "29", "14", "76", "22", "83", "71", "89" },
            { "224", "082", "152", "429", "314", "676", "922", "583", "871", "489" },
            { "5224", "7082", "9152", "9429", "8314", "4676", "7922", "2583", "9871", "0489"},
            { "55224", "87082", "59152", "69429", "38314", "54676", "87922", "62583", "99871", "20489" },
            { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" },
            { "4755224", "4287082", "7359152", "6969429", "0338314", "8254676", "8287922", "2162583", "3399871", "5520489" },
            { "84755224", "94287082", "37359152", "26969429", "40338314", "68254676", "18287922", "82162583", "73399871", "45520489" }
    };



    @Test
    public void testGenerateNdigits()
    {
        for(int digits = 1; digits <= 8; digits ++)
        {
            HOTPGenerator generator = HOTPGenerator.getInstance(digits);
            for(int counter = 0; counter < 10; counter++)
            {
                assertEquals(TEST_VECTOR_N[digits-1][counter], generator.generate(TEST_SECRET, counter));
            }
        }
    }

    @Test
    public void testCheckNdigits()
    {
        for(int digits = 1; digits <= 8; digits ++)
        {
            HOTPGenerator generator = HOTPGenerator.getInstance(digits);
            for(int counter = 0; counter < 10; counter++)
            {
                assertTrue(generator.check(TEST_VECTOR_N[digits-1][counter], TEST_SECRET, counter));
            }
        }
    }

    @Test
    public void testUnsupportedHmac()
    {
        // GIVEN
        Provider providerToRemove = null;
        for (Provider provider : Security.getProviders())
        {
            for (Provider.Service service : provider.getServices())
            {
                if("HmacSHA1".equals(service.getAlgorithm()))
                {
                    providerToRemove = provider;
                    break;

                }
            }
        }

        if(providerToRemove != null)
        {
            Security.removeProvider(providerToRemove.getName());
        }

        // WHEN
        try
        {
            HOTPGenerator.getInstance(7).generate(TEST_SECRET, 0);
        }
        catch (IllegalStateException e)
        {
            if(providerToRemove != null)
            {
                Security.addProvider(providerToRemove);
            }
            return;
        }
        fail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testTooLowLength()
    {
        // GIVEN
        int length = 0;

        // WHEN
        HOTPGenerator.getInstance(length);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHighLowLength()
    {
        // GIVEN
        int length = 9;

        // WHEN
        HOTPGenerator.getInstance(length);
    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        int length = 7;

        // WHEN
        HOTPGenerator generator = HOTPGenerator.getInstance(length);

        // THEN
        assertEquals(length, generator.getLength());
        assertEquals(Hmac.SHA1, generator.getHmac());
        assertEquals("HOTPGenerator(l=" + length + ")", generator.toString());
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        int length = 8;
        HOTPGenerator generator = HOTPGenerator.getInstance(length);

        // THEN
        boolean eqNull = generator.equals(null);
        boolean eqClass = generator.equals(new TOTPGenerator(Hmac.SHA256,  Duration.ofSeconds(30), 7));
        boolean difInst = generator.equals(new HOTPGenerator(7));
        boolean sameInst = generator.equals(new HOTPGenerator(length));
        boolean sameInst2 = generator.equals(HOTPGenerator.getInstance(length));
        boolean notSameInst1 = generator.equals(HOTPGenerator.getInstance(5));
        int hashCode = generator.hashCode();

        // END
        assertFalse(eqNull);
        assertFalse(eqClass);
        assertFalse(difInst);
        assertTrue(sameInst);
        assertTrue(sameInst2);
        assertFalse(notSameInst1);
        Assert.assertNotEquals(hashCode, HOTPGenerator.getInstance(length-1).hashCode());
        Assert.assertEquals(hashCode, new HOTPGenerator(length).hashCode());
    }


}