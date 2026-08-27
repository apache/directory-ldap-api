/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.constants.LdapSecurityConstants;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that compareCredentials fails closed (returns false) on malformed
 * stored credentials instead of escaping with unchecked exceptions
 * (NegativeArraySizeException, IllegalArgumentException, out-of-bounds...).
 * A user can store any opaque value in userPassword; a subsequent bind must
 * not crash the authenticator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class PasswordUtilMalformedCredentialsTest
{
    private static boolean compare( String stored )
    {
        return PasswordUtil.compareCredentials( Strings.getBytesUtf8( "secret" ), Strings.getBytesUtf8( stored ) );
    }


    @Test
    public void testTruncatedSshaPayloadReturnsFalse()
    {
        // Decodes to 3 bytes, less than the 20-byte SHA1 hash length :
        // previously threw NegativeArraySizeException
        assertFalse( compare( "{SSHA}AAAA" ) );
    }


    @Test
    public void testNonBase64PayloadReturnsFalse()
    {
        // Previously threw IllegalArgumentException from the Base64 decoder
        assertFalse( compare( "{SSHA}not*base64!!" ) );
    }


    @Test
    public void testTruncatedCryptPayloadReturnsFalse()
    {
        // Shorter than the 2-byte crypt salt : previously threw
        // NegativeArraySizeException
        assertFalse( compare( "{CRYPT}x" ) );
    }


    @Test
    public void testCryptMd5WithoutDollarReturnsFalse()
    {
        // No '$' between salt and hash : previously Arrays.copyOfRange
        // threw with from > to
        assertFalse( compare( "{CRYPT}$1$saltwithnodollar" ) );
    }


    @Test
    public void testShortBcryptSaltReturnsFalse()
    {
        // Salt shorter than the 29 chars BCrypt requires : previously threw
        // StringIndexOutOfBoundsException from BCrypt.hashPw
        assertFalse( compare( "{CRYPT}$2a$10$tooshort" ) );
    }


    @Test
    public void testTruncatedPkcs5s2PayloadReturnsFalse()
    {
        // Decodes to fewer bytes than the 32-byte PKCS5S2 hash length :
        // previously threw NegativeArraySizeException
        assertFalse( compare( "{PKCS5S2}AAAA" ) );
    }


    @Test
    public void testWellFormedCredentialsStillMatch()
    {
        // The fail-closed path must not affect valid credentials
        byte[] stored = PasswordUtil.createStoragePassword( Strings.getBytesUtf8( "secret" ),
            LdapSecurityConstants.HASH_METHOD_SSHA );

        assertTrue( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "secret" ), stored ) );
        assertFalse( PasswordUtil.compareCredentials( Strings.getBytesUtf8( "wrong" ), stored ) );
    }
}
