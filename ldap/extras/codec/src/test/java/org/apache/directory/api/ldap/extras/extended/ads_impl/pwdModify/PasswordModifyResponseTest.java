/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the PasswordModifyReponse codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class PasswordModifyResponseTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedResponse( new PasswordModifyFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a PasswordModifyResponse with nothing in it
     */
    @Test
    public void testDecodePasswordModifyResponseEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00  // PasswordModifyResponse ::= SEQUENCE {
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedResponseFactories().
            get( PasswordModifyResponse.EXTENSION_OID );
        PasswordModifyResponse passwordModifyResponse = ( PasswordModifyResponse ) factory.newResponse( bb );

        assertNull( passwordModifyResponse.getGenPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyResponse with an empty genPassword
     */
    @Test
    public void testDecodePasswordModifyResponseUserIdentityNull() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,             // PasswordModifyResponse ::= SEQUENCE {
                  ( byte ) 0x80, 0x00   // genPassword    [0]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedResponseFactories().
            get( PasswordModifyResponse.EXTENSION_OID );
        PasswordModifyResponse passwordModifyResponse = ( PasswordModifyResponse ) factory.newResponse( bb );

        assertNotNull( passwordModifyResponse.getGenPassword() );
        assertEquals( 0, passwordModifyResponse.getGenPassword().length );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyResponse with a genPassword
     */
    @Test
    public void testDecodePasswordModifyResponseUserIdentityValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,             // PasswordModifyResponse ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,  // genPassword    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedResponseFactories().
            get( PasswordModifyResponse.EXTENSION_OID );
        PasswordModifyResponse passwordModifyResponse = ( PasswordModifyResponse ) factory.newResponse( bb );

        assertNotNull( passwordModifyResponse.getGenPassword() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyResponse.getGenPassword() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }
}
