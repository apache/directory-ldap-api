/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.password;


import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_CRYPT;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_CRYPT_BCRYPT;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_CRYPT_MD5;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_CRYPT_SHA256;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_CRYPT_SHA512;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_MD5;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_PKCS5S2;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SHA;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SHA256;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SHA384;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SHA512;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SMD5;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SSHA;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SSHA256;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SSHA384;
import static org.apache.directory.api.ldap.model.constants.LdapSecurityConstants.HASH_METHOD_SSHA512;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.CRYPT_BCRYPT_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.CRYPT_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.CRYPT_MD5_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.CRYPT_SHA256_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.CRYPT_SHA512_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.MD5_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.PKCS5S2_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.SHA1_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.SHA256_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.SHA384_LENGTH;
import static org.apache.directory.api.ldap.model.password.PasswordUtil.SHA512_LENGTH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.util.Strings;
import org.junit.Test;


/**
 * A test for the PasswordUtil class.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordUtilTest
{

    @Test
    public void compareCredentialTest()
    {
        // Simple cases
        assertTrue( PasswordUtil.compareCredentials( null, null ) );
        assertTrue( PasswordUtil.compareCredentials( new byte[]
            {}, new byte[]
            {} ) );
        assertTrue( PasswordUtil.compareCredentials( new byte[]
            { 0x01 }, new byte[]
            { 0x01 } ) );

        // Simple failures
        assertFalse( PasswordUtil.compareCredentials( null, new byte[]
            { 0x01 } ) );
        assertFalse( PasswordUtil.compareCredentials( new byte[]
            { 0x01 }, null ) );
        assertFalse( PasswordUtil.compareCredentials( new byte[]
            { 0x01 }, new byte[]
            { 0x02 } ) );

        // With some different lengths
        assertFalse( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ),
            Strings.getBytesUtf8( "Password1 " ) ) );

        // With different passwords
        assertFalse( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ),
            Strings.getBytesUtf8( "password1" ) ) );

        // With same passwords
        assertTrue( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "Password1" ),
            Strings.getBytesUtf8( "Password1" ) ) );
    }


    @Test
    public void testPasswordPlainText()
    {
        testPassword( "secret", "secret", null, 6, 0 );
    }


    @Test
    public void testUnsupportedHashMethodIsHandledAsPlainText()
    {
        testPassword( "{XXX}abc", "{XXX}abc", null, 8, 0 );
    }


    @Test
    public void testPasswordMD5Encrypted()
    {
        testPassword( "secret", "{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ==", HASH_METHOD_MD5, MD5_LENGTH, 0 );
    }


    @Test
    public void testPasswordMD5EncryptedLowercase()
    {
        testPassword( "secret", "{md5}Xr4ilOzQ4PCOq3aQ0qbuaQ==", HASH_METHOD_MD5, MD5_LENGTH, 0 );
    }


    @Test
    public void testPasswordSMD5Encrypted()
    {
        testPassword( "secret", "{SMD5}tQ9wo/VBuKsqBtylMMCcORbnYOJFMyDJ", HASH_METHOD_SMD5, MD5_LENGTH, 8 );
    }


    @Test
    public void testPasswordSMD5EncryptedLowercase()
    {
        testPassword( "secret", "{smd5}tQ9wo/VBuKsqBtylMMCcORbnYOJFMyDJ", HASH_METHOD_SMD5, MD5_LENGTH, 8 );
    }


    @Test
    public void testPasswordSHAEncrypted()
    {
        testPassword( "secret", "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=", HASH_METHOD_SHA, SHA1_LENGTH, 0 );
    }


    @Test
    public void testPasswordSHAEncryptedLowercase()
    {
        testPassword( "secret", "{sha}5en6G6MezRroT3XKqkdPOmY/BfQ=", HASH_METHOD_SHA, SHA1_LENGTH, 0 );
    }


    @Test
    public void testPasswordSSHAEncrypted()
    {
        testPassword( "secret", "{SSHA}mjVVxasFkk59wMW4L1Ldt+YCblfhULHs03WW7g==", HASH_METHOD_SSHA, SHA1_LENGTH, 8 );
    }


    @Test
    public void testPasswordSSHAEncryptedLowercase()
    {
        testPassword( "secret", "{ssha}mjVVxasFkk59wMW4L1Ldt+YCblfhULHs03WW7g==", HASH_METHOD_SSHA, SHA1_LENGTH, 8 );
    }


    @Test
    public void testPasswordSHA256Encrypted()
    {
        testPassword( "secret", "{SHA256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=", HASH_METHOD_SHA256,
            SHA256_LENGTH, 0 );
    }


    @Test
    public void testPasswordSHA256EncryptedLowercase()
    {
        testPassword( "secret", "{sha256}K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=",
            HASH_METHOD_SHA256, SHA256_LENGTH, 0 );
    }


    @Test
    public void testPasswordSSHA256Encrypted()
    {
        testPassword( "secret", "{SSHA256}MVfpHvqPUIXJb1uZCVtX1JeDokt9EHgHMMSexe/92lb2vfMrmUHnkw==",
            HASH_METHOD_SSHA256, SHA256_LENGTH, 8 );
    }


    @Test
    public void testPasswordSSHA256EncryptedLowercase()
    {
        testPassword( "secret", "{ssha256}MVfpHvqPUIXJb1uZCVtX1JeDokt9EHgHMMSexe/92lb2vfMrmUHnkw==",
            HASH_METHOD_SSHA256, SHA256_LENGTH, 8 );
    }


    @Test
    public void testPasswordSHA384Encrypted()
    {
        testPassword( "secret", "{SHA384}WKd1ukESvjAFrkQHznV9iP2nHUBJe7gCbsrFTU4//HIyzo3jq1rLMK45dg/ufFPt",
            HASH_METHOD_SHA384, SHA384_LENGTH, 0 );
    }


    @Test
    public void testPasswordSHA384EncryptedLowercase()
    {
        testPassword( "secret", "{sha384}WKd1ukESvjAFrkQHznV9iP2nHUBJe7gCbsrFTU4//HIyzo3jq1rLMK45dg/ufFPt",
            HASH_METHOD_SHA384, SHA384_LENGTH, 0 );
    }


    @Test
    public void testPasswordSSHA384Encrypted()
    {
        testPassword( "secret", "{SSHA384}Ryj+LRp+FKIt0X6PhsqT4kK/76hO6bNeQWha0sMflaY2x2L+nSv/Z7oVMQFTde8Vttn+RFJFIL0=",
            HASH_METHOD_SSHA384, SHA384_LENGTH, 8 );
    }


    @Test
    public void testPasswordSSHA384EncryptedLowercase()
    {
        testPassword( "secret", "{ssha384}Ryj+LRp+FKIt0X6PhsqT4kK/76hO6bNeQWha0sMflaY2x2L+nSv/Z7oVMQFTde8Vttn+RFJFIL0=",
            HASH_METHOD_SSHA384, SHA384_LENGTH, 8 );
    }


    @Test
    public void testPasswordSHA512Encrypted()
    {
        testPassword( "secret",
            "{SHA512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==",
            HASH_METHOD_SHA512, SHA512_LENGTH, 0 );
    }


    @Test
    public void testPasswordSHA512EncryptedLowercase()
    {
        testPassword( "secret",
            "{sha512}vSsar3708Jvp9Szi2NWZZ02Bqp1qRCFpbcTZPdBhnWgs5WtNZKnvCXdhztmeD2cmW192CF5bDufKRpayrW/isg==",
            HASH_METHOD_SHA512, SHA512_LENGTH, 0 );
    }


    @Test
    public void testPasswordSSHA512Encrypted()
    {
        testPassword( "secret",
            "{SSHA512}ZXa+mKUUX657jXwVF4t6djmniDAZG2O2Xk8YTbmau5qWjpZ6FGH0Nql0uR18+sUxATjJbF6YHZr6GjRxVDLgknh9nUZmK26+",
            HASH_METHOD_SSHA512, SHA512_LENGTH, 8 );
    }


    @Test
    public void testPasswordSSHA512EncryptedLowercase()
    {
        testPassword( "secret",
            "{ssha512}ZXa+mKUUX657jXwVF4t6djmniDAZG2O2Xk8YTbmau5qWjpZ6FGH0Nql0uR18+sUxATjJbF6YHZr6GjRxVDLgknh9nUZmK26+",
            HASH_METHOD_SSHA512, SHA512_LENGTH, 8 );
    }


    @Test
    public void testPasswordPKCS5S2Encrypted()
    {
        testPassword( "secret", "{PKCS5S2}3L9Bz29r+5fGHlItzYcMlWeJHl7xWYTlaeEOzzx5aHntdP4DyK4hKQCidxcHMwz8",
            HASH_METHOD_PKCS5S2, PKCS5S2_LENGTH, 16 );
    }


    @Test
    public void testPasswordPKCS5S2EncryptedLowercase()
    {
        testPassword( "secret", "{pkcs5s2}3L9Bz29r+5fGHlItzYcMlWeJHl7xWYTlaeEOzzx5aHntdP4DyK4hKQCidxcHMwz8",
            HASH_METHOD_PKCS5S2, PKCS5S2_LENGTH, 16 );
    }


    @Test
    public void testPasswordCRYPTEncrypted()
    {
        testPassword( "secret", "{CRYPT}qFkH8Z1woBlXw", HASH_METHOD_CRYPT, CRYPT_LENGTH, 2 );
    }


    @Test
    public void testPasswordCRYPTEncryptedLowercase()
    {
        testPassword( "secret", "{crypt}qFkH8Z1woBlXw", HASH_METHOD_CRYPT, CRYPT_LENGTH, 2 );
    }


    @Test
    public void testPasswordCRYPT1Encrypted()
    {
        testPassword( "secret", "{CRYPT}$1$salt$ez2vlPGdaLYkJam5pWs/Y1", HASH_METHOD_CRYPT_MD5, CRYPT_MD5_LENGTH, 4 );
    }


    @Test
    public void testPasswordCRYPT1EncryptedLowercase()
    {
        testPassword( "secret", "{crypt}$1$salt$ez2vlPGdaLYkJam5pWs/Y1", HASH_METHOD_CRYPT_MD5, CRYPT_MD5_LENGTH, 4 );
    }


    @Test
    public void testPasswordCRYPT5Encrypted()
    {
        testPassword( "secret", "{CRYPT}$5$salt$kpa26zwgX83BPSR8d7w93OIXbFt/d3UOTZaAu5vsTM6", HASH_METHOD_CRYPT_SHA256, CRYPT_SHA256_LENGTH,
            4 );
    }


    @Test
    public void testPasswordCRYPT5EncryptedLowercase()
    {
        testPassword( "secret", "{crypt}$5$salt$kpa26zwgX83BPSR8d7w93OIXbFt/d3UOTZaAu5vsTM6", HASH_METHOD_CRYPT_SHA256, CRYPT_SHA256_LENGTH,
            4 );
    }


    @Test
    public void testPasswordCRYPT6Encrypted()
    {
        testPassword( "secret",
            "{CRYPT}$6$salt$egUxKNxDs8kPfh8iPMNcosMhb2eWah6d3R44JDm5Rj/j/XWR5E33QPd0YmHXoDHOIDR6kL5D3JcQcz0O8FHE00",
            HASH_METHOD_CRYPT_SHA512, CRYPT_SHA512_LENGTH, 4 );
    }


    @Test
    public void testPasswordCRYPT6EncryptedLowercase()
    {
        testPassword( "secret",
            "{crypt}$6$salt$egUxKNxDs8kPfh8iPMNcosMhb2eWah6d3R44JDm5Rj/j/XWR5E33QPd0YmHXoDHOIDR6kL5D3JcQcz0O8FHE00",
            HASH_METHOD_CRYPT_SHA512, CRYPT_SHA512_LENGTH, 4 );
    }


    @Test
    public void testPasswordCRYPT2aEncrypted()
    {
        testPassword( "secret",
            "{CRYPT}$2a$06$LH2xIb/TZmajuLJGDNuegeeY.SCwkg6YAVLNXTh8n4Xfb1uwmLXg6",
            HASH_METHOD_CRYPT_BCRYPT, CRYPT_BCRYPT_LENGTH, 29 );
    }


    @Test
    public void testPasswordCRYPT2aEncryptedLowercase()
    {
        testPassword( "secret",
            "{crypt}$2a$06$LH2xIb/TZmajuLJGDNuegeeY.SCwkg6YAVLNXTh8n4Xfb1uwmLXg6",
            HASH_METHOD_CRYPT_BCRYPT, CRYPT_BCRYPT_LENGTH, 29 );
    }


    private void testPassword(String plainText, String encrypted, LdapSecurityConstants algorithm, int passwordLength,
                              int saltLength )
    {
        // assert findAlgorithm
        assertEquals( algorithm, PasswordUtil.findAlgorithm( Strings.getBytesUtf8( encrypted ) ) );

        // assert compareCredentials
        assertTrue(
            PasswordUtil.compareCredentials( Strings.getBytesUtf8( plainText ), Strings.getBytesUtf8( encrypted ) ) );

        // assert splitCredentials
        PasswordDetails passwordDetails = PasswordUtil.splitCredentials( Strings.getBytesUtf8( encrypted ) );
        assertEquals( algorithm, passwordDetails.getAlgorithm() );
        if ( saltLength == 0 )
        {
            assertNull( passwordDetails.getSalt() );
        }
        else
        {
            assertNotNull( passwordDetails.getSalt() );
            assertEquals( saltLength, passwordDetails.getSalt().length );
        }
        assertNotNull( passwordDetails.getPassword() );
        assertEquals( passwordLength, passwordDetails.getPassword().length );

        // assert createStoragePassword / compareCredentials roundtrip
        byte[] generated = PasswordUtil.createStoragePassword( plainText, algorithm );
        assertTrue(
            PasswordUtil.compareCredentials( Strings.getBytesUtf8( plainText ), generated ) );
    }

}
