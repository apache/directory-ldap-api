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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Iterator;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the GracefulDisconnectTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class GracefulDisconnectResponseTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedResponse( new GracefulDisconnectFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a GracefulDisconnect
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectSuccess() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x6E,                             // GracefulDisconnec ::= SEQUENCE {
                  0x02, 0x01, 0x01,                     // timeOffline INTEGER (0..720) DEFAULT 0,
                  ( byte ) 0x80, 0x01, 0x01,            // delay INTEGER (0..86400) DEFAULT 0
                    0x30, 0x66,                         // replicatedContexts Referral OPTIONAL
                      0x04, 0x1F,     
                        'l', 'd', 'a', 'p', ':', '/', '/', 'd',
                        'i', 'r', 'e', 'c', 't', 'o', 'r', 'y',
                        '.', 'a', 'p', 'a', 'c', 'h', 'e', '.',
                        'o', 'r', 'g', ':', '8', '0', '/',
                      0x04, 0x43,
                        'l', 'd', 'a', 'p', ':', '/', '/', 'l', 
                        'd', 'a', 'p', '.', 'n', 'e', 't', 's', 
                        'c', 'a', 'p', 'e', '.', 'c', 'o', 'm', 
                        '/', 'o', '=', 'B', 'a', 'b', 's', 'c', 
                        'o', ',', 'c', '=', 'U', 'S', '?', '?', 
                        '?', '(', 'i', 'n', 't', '=', '%', '5', 
                        'c', '0', '0', '%', '5', 'c', '0', '0', 
                        '%', '5', 'c', '0', '0', '%', '5', 'c', 
                        '0', '4', ')'
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 2, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );
        
        Iterator<String> ldapUrls = gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().iterator();
        assertEquals( "ldap://directory.apache.org:80/", ldapUrls.next() );
        assertEquals( "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)", ldapUrls.next() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline only
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOffline() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,             // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x01, 0x01      // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a delay only
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectDelay() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,                     // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x01, 0x01     // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );


        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline and a delay
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOfflineDelay() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                     // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // timeOffline INTEGER (0..720) DEFAULT 0,
                  ( byte ) 0x80, 0x01, 0x01,    // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with replicatedContexts only
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectReplicatedContextsOnly() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            {
                0x30, 0x68,             // GracefulDisconnec ::= SEQUENCE {
                  0x30, 0x66,           // replicatedContexts Referral OPTIONAL
                    0x04, 0x1F,     
                      'l', 'd', 'a', 'p', ':', '/', '/', 'd',
                      'i', 'r', 'e', 'c', 't', 'o', 'r', 'y',
                      '.', 'a', 'p', 'a', 'c', 'h', 'e', '.',
                      'o', 'r', 'g', ':', '8', '0', '/',
                    0x04, 0x43,
                      'l', 'd', 'a', 'p', ':', '/', '/', 'l', 
                      'd', 'a', 'p', '.', 'n', 'e', 't', 's', 
                      'c', 'a', 'p', 'e', '.', 'c', 'o', 'm', 
                      '/', 'o', '=', 'B', 'a', 'b', 's', 'c', 
                      'o', ',', 'c', '=', 'U', 'S', '?', '?', 
                      '?', '(', 'i', 'n', 't', '=', '%', '5', 
                      'c', '0', '0', '%', '5', 'c', '0', '0', 
                      '%', '5', 'c', '0', '0', '%', '5', 'c', 
                      '0', '4', ')'

            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 2, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );
        
        Iterator<String> ldapUrls = gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().iterator();
        assertEquals( "ldap://directory.apache.org:80/", ldapUrls.next() );
        assertEquals( "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)", ldapUrls.next() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a empty GracefulDisconnect
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulDisconnectEmpty() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00 // GracefulDisconnect ::= SEQUENCE {
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline off limit
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOfflineOffLimit()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,                         // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x02, 0x03, ( byte ) 0xE8   // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a delay off limit
     */
    @Test
    public void testDecodeGracefulDisconnectDelayOffLimit()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x05,                             // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x03,
                    0x01, ( byte ) 0x86, ( byte ) 0xA0  // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty TimeOffline
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOfflineEmpty()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,         // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x00        // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty delay
     */
    @Test
    public void testDecodeGracefulDisconnectDelayEmpty()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,                 // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x00       // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty replicated
     * contexts
     */
    @Test
    public void testDecodeGracefulDisconnectReplicatedContextsEmpty()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,         // GracefulDisconnect ::= SEQUENCE {
                  0x30, 0x00        // replicatedContexts Referral OPTIONAL
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an invalid replicated
     * context
     */
    @Test
    public void testDecodeGracefulDisconnectReplicatedContextsInvalid()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,             // GracefulDisconnect ::= SEQUENCE {
                  0x30, 0x02,           // replicatedContexts Referral OPTIONAL
                    0x04, 0x00 
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newResponse( bb );
        } );
    }
}
