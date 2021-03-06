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


/**
 * List of standard cipher transformations which are valid as
 * arguments for {@link javax.crypto.Cipher#getInstance(String)}.
 *
 * <p>
 * The list here is a copy from Java SE 7 JavaDoc. Therefore,
 * they may not be supported in older Java SE environments.
 * </p>
 *
 * @see <a href="http://docs.oracle.com/javase/7/docs/api/javax/crypto/Cipher.html"
 *      >javax.crypto.Cipher</a>
 *
 * @author Takahiko Kawasaki
 */
public class StandardCipherTransformations
{
    /**
     * AES/CBC/NoPadding (128)
     */
    public static final String AES_CBC_NOPADDING = "AES/CBC/NoPadding";


    /**
     * AES/CBC/PKCS5Padding (128)
     */
    public static final String AES_CBC_PKCS5PADDING = "AES/CBC/PKCS5Padding";


    /**
     * AES/ECB/NoPadding (128)
     */
    public static final String AES_ECB_NOPADDING = "AES/ECB/NoPadding";


    /**
     * AES/ECB/PKCS5Padding (128)
     */
    public static final String AES_ECB_PKCS5PADDING = "AES/ECB/PKCS5Padding";


    /**
     * DES/CBC/NoPadding (56)
     */
    public static final String DES_CBC_NOPADDING = "DES/CBC/NoPadding";


    /**
     * DES/CBC/PKCS5Padding (56)
     */
    public static final String DES_CBC_PKCS5PADDING = "DES/CBC/PKCS5Padding";


    /**
     * DES/ECB/NoPadding (56)
     */
    public static final String DES_ECB_NOPADDING = "DES/ECB/NoPadding";


    /**
     * DES/ECB/PKCS5Padding (56)
     */
    public static final String DES_ECB_PKCS5PADDING = "DES/ECB/PKCS5Padding";


    /**
     * DESede/CBC/NoPadding (168)
     */
    public static final String DESEDE_CBC_NOPADDING = "DESede/CBC/NoPadding";


    /**
     * DESede/CBC/PKCS5Padding (168)
     */
    public static final String DESEDE_CBC_PKCS5PADDING = "DESede/CBC/PKCS5Padding";


    /**
     * DESede/ECB/NoPadding (168)
     */
    public static final String DESEDE_ECB_NOPADDING = "DESede/ECB/NoPadding";


    /**
     * DESede/ECB/PKCS5Padding (168)
     */
    public static final String DESEDE_ECB_PKCS5PADDING = "DESede/ECB/PKCS5Padding";


    /**
     * RSA/ECB/PKCS1Padding (1024, 2048)
     */
    public static final String RSA_ECB_PKCS1PADDING = "RSA/ECB/PKCS1Padding";


    /**
     * RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
     */
    public static final String RSA_ECB_OAEPWITHSHA1ANDMGF1PADDING = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";


    /**
     * RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
     */
    public static final String RSA_ECB_OAEPWITHSHA256ANDMGF1PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";


    private StandardCipherTransformations()
    {
    }
}
