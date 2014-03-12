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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import org.apache.commons.codec.BinaryDecoder;
import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.net.QuotedPrintableCodec;
import org.apache.commons.codec.net.URLCodec;
import org.junit.Test;


/**
 * Tests for {@link AESCipher}.
 *
 * @author Takahiko Kawasaki
 */
public class AESCipherTest
{
    private static final boolean DEBUG = false;


    private <TCoder extends BinaryEncoder & BinaryDecoder> void doTest(String plain, String key, String iv, TCoder coder)
    {
        AESCipher cipher = new AESCipher();

        if (coder != null)
        {
            cipher.setCoder(coder);
        }

        cipher.setKey(key, iv);

        // Encrypt.
        String encrypted = cipher.encrypt(plain);

        if (iv == null)
        {
            byte[] iv2 = cipher.getCipher().getIV();
            cipher.setKey(key, iv2);
        }

        // Decrypt.
        String decrypted = cipher.decrypt(encrypted);

        if (DEBUG)
        {
            System.out.println("----------");
            System.out.println("codec     = " + ((coder != null) ? coder.getClass().getSimpleName() : "default"));
            System.out.println("plain     = " + plain);
            System.out.println("encrypted = " + encrypted);
            System.out.println("decrypted = " + decrypted);
        }

        assertNotEquals(plain, encrypted);
        assertEquals(plain, decrypted);
    }


    @Test
    public void test1()
    {
        doTest("hello", "key", "iv", null);
    }


    @Test
    public void test2()
    {
        doTest("hello", "1234567890123456", "1234567890123456", new Hex());
    }


    @Test
    public void test3()
    {
        doTest("hello", "12345678901234567890", "12345678901234567890", new BinaryCodec());
    }


    @Test
    public void test4()
    {
        doTest("hello", "key", null, new URLCodec());
    }


    @Test
    public void test5()
    {
        doTest("hello", "1234567890123456", null, new QuotedPrintableCodec());
    }


    @Test
    public void test6()
    {
        doTest("hello", "12345678901234567890", null, null);
    }


    @Test
    public void test7()
    {
        doTest("hello", null, null, null);
    }
}
