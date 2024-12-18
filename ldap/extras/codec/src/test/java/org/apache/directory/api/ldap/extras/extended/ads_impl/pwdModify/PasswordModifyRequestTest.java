/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the PasswordModifyRequest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class PasswordModifyRequestTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedRequest( new PasswordModifyFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a PasswordModifyRequest with nothing in it
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00, // PasswordModifyRequest ::= SEQUENCE {
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNull( passwordModifyRequest.getUserIdentity() );
        assertNull( passwordModifyRequest.getOldPassword() );
        assertNull( passwordModifyRequest.getNewPassword() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );
        
        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityNull() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x00       // userIdentity    [0]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( 0, passwordModifyRequest.getUserIdentity().length );
        assertNull( passwordModifyRequest.getOldPassword() );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );
        
        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNull( passwordModifyRequest.getOldPassword() );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * an empty newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPasswordEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x08,                   // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,        // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x00         // newPassword    [2]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNull( passwordModifyRequest.getOldPassword() );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( 0, passwordModifyRequest.getNewPassword().length );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * a newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPassword() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x0C,                     // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,          // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x04,          // newPassword    [2]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNull( passwordModifyRequest.getOldPassword() );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( passwordModifyRequest.getNewPassword() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x08,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x00       // oldPassword    [1]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( 0, passwordModifyRequest.getOldPassword().length );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x0C,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and empty newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordNull() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x0E,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h',
                  ( byte ) 0x82, 0x00       // newPassword    [2]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( 0, passwordModifyRequest.getNewPassword().length );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and a newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x12,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h',
                  ( byte ) 0x82, 0x04,      // newPassword    [2]  OCTET STRING OPTIONAL
                    'i', 'j', 'k', 'l'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNotNull( passwordModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getUserIdentity() ) );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( "ijkl", Strings.utf8ToString( passwordModifyRequest.getNewPassword() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordNull() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,             // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x00   // oldPassword    [1]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNull( passwordModifyRequest.getUserIdentity() );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( 0, passwordModifyRequest.getOldPassword().length );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNull( passwordModifyRequest.getUserIdentity() );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNull( passwordModifyRequest.getNewPassword() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * empty  newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x08,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x00       // newPassword    [2]  OCTET STRING OPTIONAL
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNull( passwordModifyRequest.getUserIdentity() );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( 0, passwordModifyRequest.getNewPassword().length );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * newPassword
     * 
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordValue() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x0C,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x04,      // newPassword    [2]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            };

        PasswordModifyFactory factory = ( PasswordModifyFactory ) codec.getExtendedRequestFactories().
            get( PasswordModifyRequest.EXTENSION_OID );
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) factory.newRequest( bb );
        
        assertNull( passwordModifyRequest.getUserIdentity() );
        assertNotNull( passwordModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( passwordModifyRequest.getOldPassword() ) );
        assertNotNull( passwordModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( passwordModifyRequest.getNewPassword() ) );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordModifyRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }
}
