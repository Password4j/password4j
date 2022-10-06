package com.password4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;

import org.junit.Assert;
import org.junit.Test;

import com.password4j.types.Hmac;


public class TOTPGeneratorTest
{

    private static final byte[][] TEST_SECRET = {
            "12345678901234567890".getBytes(StandardCharsets.UTF_8),
            "12345678901234567890123456789012".getBytes(StandardCharsets.UTF_8),
            "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.UTF_8)
    };

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

    private static final String[] TEST_VECTOR_TIME = {
            "94287082", "46119246", "90693936", "07081804", "68084774", "25091201",
            "14050471", "67062674", "99943326", "89005924", "91819424", "93441116",
            "69279037", "90698825", "38618901", "65353130", "77737706", "47863826"
    };

    private static final long[] TEST_TIME_SECONDS = { 59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L };

    private static final Hmac[] TEST_HMAC = { Hmac.SHA1, Hmac.SHA256, Hmac.SHA512 };



    @Test
    public void testGenerateNdigits()
    {
        Duration duration = Duration.ofMillis(30000);
        for(int digits = 1; digits <= 8; digits ++)
        {
            TOTPGenerator generator = TOTPGenerator.getInstance(Hmac.SHA1, duration, digits);
            for(int step = 0; step < 10; step++)
            {
                Instant instant = Instant.ofEpochMilli(30000 * step);
                assertEquals(TEST_VECTOR_N[digits-1][step], generator.generate(TEST_SECRET[0], instant));
            }
        }
    }


    @Test
    public void testGenerateOverTime()
    {
        int length = 8;
        Duration duration = Duration.ofSeconds(30);

        for(int t = 0; t < TEST_VECTOR_TIME.length; t++)
        {
            assertEquals(TEST_VECTOR_TIME[t], TOTPGenerator.getInstance(TEST_HMAC[t % 3], duration, length).generate(TEST_SECRET[t % 3], Instant.ofEpochSecond(TEST_TIME_SECONDS[(int)(t / 3.0)])));
        }

    }

    @Test
    public void testAccessors()
    {
        // GIVEN
        Hmac hmac = Hmac.SHA512;
        Duration duration = Duration.ofSeconds(45);
        int length = 7;

        // WHEN
        TOTPGenerator generator = TOTPGenerator.getInstance(hmac, duration, length);

        // THEN
        assertEquals(length, generator.getLength());
        assertEquals(hmac, generator.getHmac());
        assertEquals(duration, generator.getDuration());
        assertEquals("TOTPGenerator(a=" + hmac.name().toUpperCase() + ", d=" + duration.toMillis() + ", l=" + length + ")", generator.toString());
    }

    @Test
    public void testEquality()
    {
        // GIVEN
        Hmac hmac = Hmac.SHA256;
        int length = 8;
        Duration duration = Duration.ofSeconds(30);
        TOTPGenerator generator = TOTPGenerator.getInstance(hmac, duration, length);

        // THEN
        boolean eqNull = generator.equals(null);
        boolean eqClass = generator.equals(new HOTPGenerator(7));
        boolean difInst = generator.equals(new TOTPGenerator(hmac, duration, length - 1));
        boolean difInst2 = generator.equals(new TOTPGenerator(Hmac.SHA1, duration, length));
        boolean sameInst = generator.equals(new TOTPGenerator(hmac, duration, length));
        boolean sameInst2 = generator.equals(TOTPGenerator.getInstance(hmac, duration, length));
        boolean notSameInst1 = generator.equals(TOTPGenerator.getInstance(hmac, Duration.ofSeconds(45), length));
        int hashCode = generator.hashCode();

        // END
        assertFalse(eqNull);
        assertFalse(eqClass);
        assertFalse(difInst);
        assertFalse(difInst2);
        assertTrue(sameInst);
        assertTrue(sameInst2);
        assertFalse(notSameInst1);
        Assert.assertNotEquals(hashCode, TOTPGenerator.getInstance(Hmac.SHA1, duration, length).hashCode());
        Assert.assertEquals(hashCode, new TOTPGenerator(hmac, duration, length).hashCode());
    }


}