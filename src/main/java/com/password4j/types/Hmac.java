/*
 *  (C) Copyright 2021 Password4j (http://password4j.com/).
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

package com.password4j.types;

import com.password4j.CompressedPBKDF2Function;


/**
 * Static representation of the commonly supported
 * Hmac variants.
 */
public enum Hmac
{

    SHA1(160, 1), //
    SHA224(224, 2), //
    SHA256(256, 3), //
    SHA384(384, 4), //
    SHA512(512, 5);

    private final int bits;

    private final int code;

    /**
     * @param bits length of the produced hash
     * @param code uid used by {@link CompressedPBKDF2Function}
     */
    Hmac(int bits, int code)
    {
        this.bits = bits;
        this.code = code;
    }

    /**
     * Finds the enum associated with the given code
     *
     * @param code a numeric uid that identifies the algorithm
     * @return a {@link Hmac} enum. Null if the code is not present in this enum
     */
    public static Hmac fromCode(int code)
    {
        for (Hmac alg : values())
        {
            if (alg.code() == code)
            {
                return alg;
            }
        }
        return null;
    }

    /**
     * @return length of the algorithm in bits
     */
    public int bits()
    {
        return bits;
    }

    /**
     * @return the numeric uid used in {@link CompressedPBKDF2Function}
     */
    public int code()
    {
        return code;
    }

    @Override
    public String toString()
    {
        return "PBKDF2WithHmac" + this.name();
    }
}
