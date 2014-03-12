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
import org.apache.commons.codec.binary.BinaryCodec;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;


/**
 * Tests for {@link AESCipher}.
 *
 * @author Takahiko Kawasaki
 */
public class AESCipherTest
{
    private void doTest(AESCipher cipher)
    {
        doTest(cipher, "abcdefghijklmnopqrstuvwxyz");
    }


    private void doTest(AESCipher cipher, String input)
    {
        String encrypted = cipher.encrypt(input);
        assertNotEquals(input, encrypted);

        String decrypted = cipher.decrypt(encrypted);
        assertEquals(input, decrypted);
    }


    @Test
    public void test1()
    {
        AESCipher cipher = new AESCipher().setKey("abcdefg");
        doTest(cipher);
    }


    @Test
    public void test2()
    {
        AESCipher cipher = new AESCipher(new Hex()).setKey("12345678901234567890");
        doTest(cipher);
    }


    @Test
    public void test3()
    {
        AESCipher cipher = new AESCipher(new BinaryCodec()).setKey("abcdefg", "123456");
        doTest(cipher);
    }
}
