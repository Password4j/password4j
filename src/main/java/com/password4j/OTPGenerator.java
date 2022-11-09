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

import com.password4j.types.Hmac;

import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

abstract class OTPGenerator
{
    private static final int[] DIGITS_POWER = {10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000};

    protected int length;

    protected Hmac hmac;

    OTPGenerator(Hmac hmac, int length)
    {
        this.length = length;
        this.hmac = hmac;
    }


    protected String generate(byte[] key, long counter)
    {
        Mac mac = getMac();
        try
        {
            byte[] buffer = getBuffer(counter, mac);

            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "RAW");
            mac.init(secretKeySpec);
            mac.update(buffer, 0, 8);
            mac.doFinal(buffer, 0);

            int offset = buffer[buffer.length - 1] & 0xf;


            int binary = ((buffer[offset] & 0x7f) << 24)
                    | ((buffer[offset + 1] & 0xff) << 16)
                    | ((buffer[offset + 2] & 0xff) << 8)
                    | (buffer[offset + 3] & 0xff);

            int result = binary % DIGITS_POWER[length - 1];

            StringBuilder sb = new StringBuilder(Integer.toString(result));
            while (sb.length() < length)
            {
                sb.insert(0, '0');
            }
            return sb.toString();
        }
        catch (InvalidKeyException e)
        {
            throw new IllegalStateException("Cannot use secret as key.", e);
        }
        catch (ShortBufferException e)
        {
            throw new IllegalArgumentException("Buffer is not aligned with " + mac.getAlgorithm() + "'s length.", e);
        }
    }

    public boolean check(String otp, byte[] secret, long counter)
    {
        return Utils.slowEquals(otp, generate(secret, counter));
    }

    private static byte[] getBuffer(long counter, Mac mac)
    {
        byte[] buffer = new byte[mac.getMacLength()];
        buffer[0] = (byte) ((counter & 0xff00000000000000L) >>> 56);
        buffer[1] = (byte) ((counter & 0x00ff000000000000L) >>> 48);
        buffer[2] = (byte) ((counter & 0x0000ff0000000000L) >>> 40);
        buffer[3] = (byte) ((counter & 0x000000ff00000000L) >>> 32);
        buffer[4] = (byte) ((counter & 0x00000000ff000000L) >>> 24);
        buffer[5] = (byte) ((counter & 0x0000000000ff0000L) >>> 16);
        buffer[6] = (byte) ((counter & 0x000000000000ff00L) >>> 8);
        buffer[7] = (byte)  (counter & 0x00000000000000ffL);
        return buffer;
    }


    Mac getMac()
    {
        String algorithm = "Hmac" + hmac.name().toUpperCase();
        try
        {
            return Mac.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("Cannot find definition for " + algorithm);
        }
    }

    static void checkLength(int length)
    {
        if(length < 1 || length > DIGITS_POWER.length)
        {
            throw new IllegalArgumentException("Length must be between 1 and 8 inclusive. Got " + length + ".");
        }
    }

    public Hmac getHmac()
    {
        return hmac;
    }

    public int getLength()
    {
        return length;
    }
}
