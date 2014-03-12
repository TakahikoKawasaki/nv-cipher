/*
 * Copyright (C) 2014 Neo Visionaries Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.neovisionaries.security;


import java.io.UnsupportedEncodingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * Utility methods for internal implementation.
 *
 * @author Takahiko Kawasaki
 */
class Utils
{
    private Utils()
    {
    }


    /**
     * Get bytes by {@code input.getBytes("UTF-8")}.
     */
    public static byte[] getBytesUTF8(String string)
    {
        if (string == null)
        {
            return null;
        }

        try
        {
            // Convert the string to a byte array encoded in UTF-8.
            return string.getBytes("UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            // This won't happen.
            return null;
        }
    }


    /**
     * Build a {@code String} instance by {@code new String(input, "UTF-8")}.
     */
    public static String toStringUTF8(byte[] input)
    {
        if (input == null)
        {
            return null;
        }

        try
        {
            return new String(input, "UTF-8");
        }
        catch (UnsupportedEncodingException e)
        {
            // This won't happen.
            return null;
        }
    }


    public static byte[] ensureSize(byte[] data, int size)
    {
        if (data == null)
        {
            return new byte[size];
        }

        if (size <= data.length)
        {
            return data;
        }

        byte[] data2 = new byte[size];

        System.arraycopy(data, 0, data2, 0, data.length);

        return data2;
    }


    public static SecretKeySpec createSecretKeySpec(String key, String algorithm, int size)
    {
        return createSecretKeySpec(getBytesUTF8(key), algorithm, size);
    }


    public static SecretKeySpec createSecretKeySpec(byte[] key, String algorithm, int size)
    {
        key = ensureSize(key, size);

        return new SecretKeySpec(key, 0, size, algorithm);
    }


    public static IvParameterSpec createIvParameterSpec(String iv, int size)
    {
        return createIvParameterSpec(getBytesUTF8(iv), size);
    }


    public static IvParameterSpec createIvParameterSpec(byte[] iv, int size)
    {
        iv = ensureSize(iv, size);

        return new IvParameterSpec(iv, 0, size);
    }
}
