package com.password4j;

import java.util.Locale;

public class Symbols
{

    public static final String LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz";

    public static final String UPPERCASE_LETTERS = LOWERCASE_LETTERS.toUpperCase(Locale.ENGLISH);

    public static final String DIGITS = "0123456789";

    public static final String SPECIALS_CHARACTERS = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    public static final String LETTERS = LOWERCASE_LETTERS + UPPERCASE_LETTERS;

    public static final String LOWER_ALPHANUMERIC = LOWERCASE_LETTERS + DIGITS;

    public static final String UPPER_ALPHANUMERIC = UPPERCASE_LETTERS + DIGITS;

    public static final String ALPHANUMERIC = LETTERS + DIGITS;

    public static final String PRINTABLE = ALPHANUMERIC + SPECIALS_CHARACTERS;




    static final char[] LOWERCASE_LETTERS_CHARS = LOWERCASE_LETTERS.toCharArray();

    static final char[] UPPERCASE_LETTERS_CHARS = UPPERCASE_LETTERS.toCharArray();

    static final char[] DIGITS_CHARS = DIGITS.toCharArray();

    static final char[] SPECIALS_CHARACTERS_CHARS = SPECIALS_CHARACTERS.toCharArray();

    private Symbols()
    {
        //
    }


}
