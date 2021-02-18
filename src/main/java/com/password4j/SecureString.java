/*
 *  (C) Copyright 2020 Password4j (http://password4j.com/).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package com.password4j;

import java.util.Arrays;


/**
 * More secure implementation of {@link CharSequence} than {@link String}, preventing heap memory attacks.
 * <p>
 * Like {@link String}, this {@link CharSequence} implementation has an underlying array of {@code char}s.
 * The sequence however is not stored in the String pool and the array of {@code char}s lives
 * temporary in the heap memory.
 *
 * @author David Bertoldi
 * @since 1.2.0
 */
public class SecureString implements CharSequence
{
    private final char[] chars;

    /**
     * Creates a {@link SecureString} from an array of {@code char}s.
     * The sequence is never put in the String pool.
     *
     * @param chars sequence of characters
     * @throws NullPointerException if null is passed
     * @since 1.2.0
     */
    public SecureString(char[] chars)
    {
        this.chars = new char[chars.length];
        System.arraycopy(chars, 0, this.chars, 0, chars.length);
    }

    /**
     * Creates a {@link SecureString} from an array of {@code char}s.
     * Important: if the second argument is true, the original array is zeroed after the object creation! Each {@code char} is replaced
     * with {@link Character#MIN_VALUE}
     * <p>
     * The sequence is never put in the String pool.
     *
     * @param chars       sequence of characters
     * @param eraseSource if true, the original array is zeroed
     * @throws NullPointerException if null is passed
     * @since 1.2.0
     */
    public SecureString(char[] chars, boolean eraseSource)
    {
        this(chars);
        if (eraseSource)
        {
            clear(chars);
        }
    }

    /**
     * Creates a {@link SecureString} from a subsequence of an array of {@code char}s.
     * The sequence is never put in the String pool.
     *
     * @param chars sequence of characters
     * @param start index of the beginning of the subsequence
     * @param end   index of the end of the subsequence
     * @throws NullPointerException if null is passed as array of {@code char}s
     * @since 1.2.0
     */
    public SecureString(char[] chars, int start, int end)
    {
        this.chars = new char[end - start];
        System.arraycopy(chars, start, this.chars, 0, this.chars.length);
        clear(chars);
    }

    private static synchronized void clear(char[] chars)
    {
        Arrays.fill(chars, Character.MIN_VALUE);
    }

    /**
     * @return length of the underlying array of {@code char}s.
     * @since 1.2.0
     */
    @Override
    public synchronized int length()
    {
        return chars.length;
    }

    /**
     * @param index position in the underlying array of {@code char}s.
     * @return the {@code char} in the given position
     * @since 1.2.0
     */
    @Override
    public synchronized char charAt(int index)
    {
        return chars[index];
    }

    /**
     * Creates a {@link SecureString} from a subsequence of this object.
     *
     * @param start index of the beginning of the subsequence
     * @param end   index of the end of the subsequence
     * @see SecureString#SecureString(char[], int, int)
     * @since 1.2.0
     */
    @Override
    public synchronized CharSequence subSequence(int start, int end)
    {
        return new SecureString(this.chars, start, end);
    }

    /**
     * Manually clear the underlying array holding the characters
     *
     * @since 1.2.0
     */
    public void clear()
    {
        synchronized (chars)
        {
            clear(chars);
        }
    }

    /**
     * Returns a constant {@link String} in order to prevent data leaks due
     * to accidental usage of a {@link SecureString} objects in methods like
     * {@link java.io.PrintStream#print(Object)}, loggers, etc.
     *
     * @return a masked version of this object.
     * @since 1.2.0
     */
    @Override
    public String toString()
    {
        return "SecureString[****]";
    }

    /**
     * Constant time equality to avoid potential timing attacks.
     *
     * @param other object
     * @since 1.2.1
     */
    @Override
    public synchronized boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }
        if (!(other instanceof CharSequence))
        {
            return false;
        }
        CharSequence that = (CharSequence) other;

        if (chars.length != that.length())
        {
            return false;
        }

        int equals = 0;
        for (int i = 0; i < chars.length; i++)
        {
            equals |= chars[i] ^ that.charAt(i);
        }

        return equals == 0;
    }

    @Override
    public synchronized int hashCode()
    {
        return Arrays.hashCode(chars);
    }
}
