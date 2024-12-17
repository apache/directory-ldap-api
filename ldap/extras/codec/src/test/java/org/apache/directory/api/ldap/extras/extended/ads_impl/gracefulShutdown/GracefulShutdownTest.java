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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the GracefulShutdownTest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class GracefulShutdownTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedRequest( new GracefulShutdownFactory( codec ) );
    }

    
    /**
     * Test the decoding of a GracefulShutdown
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownSuccess() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                 // GracefulShutdown ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // timeOffline INTEGER (0..720) DEFAULT 0,
                  ( byte ) 0x80, 0x01, 0x01 // delay INTEGER (0..86400) DEFAULT 0
                                            // }
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 1, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 1, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulShutdown with a timeOffline only
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownTimeOffline() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,             // GracefulShutdown ::= SEQUENCE {
                  0x02, 0x01, 0x01      // timeOffline INTEGER (0..720) DEFAULT 0,
        };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 1, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 0, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulShutdown with a delay only
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownDelay() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,                 // GracefulShutdown ::= SEQUENCE {
                  ( byte ) 0x80, 0x01, 0x01 // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 0, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 1, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );
        
        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a empty GracefulShutdown
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownEmpty() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00 // GracefulShutdown ::= SEQUENCE {
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 0, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 0, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulShutdown with a delay above 128
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownDelayHigh() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,                                 // GracefulShutdown ::= SEQUENCE {
                  ( byte ) 0x80, 0x02, 0x01, ( byte ) 0xF4  // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 0, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 500, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulShutdown with a delay equals 32767
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownDelay32767() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,                                 // GracefulShutdown ::= SEQUENCE {
                  ( byte ) 0x80, 0x02, 0x7F, ( byte ) 0xFF  // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 0, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 32767, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulShutdown with a delay above 32768
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeGracefulShutdownDelay32768() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x05,             // GracefulShutdown ::= SEQUENCE {
                                        // delay INTEGER (0..86400) DEFAULT 0
                ( byte ) 0x80, 0x03, 0x00, ( byte ) 0x80, ( byte ) 0x00 
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );
        GracefulShutdownRequest gracefulShutdownRequest = 
            ( GracefulShutdownRequest ) factory.newRequest( bb );

        assertEquals( 0, gracefulShutdownRequest.getTimeOffline() );
        assertEquals( 32768, gracefulShutdownRequest.getDelay() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulShutdownRequest );

        assertArrayEquals( bb,  asn1Buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a GracefulShutdown with a timeOffline off limit
     */
    @Test
    public void testDecodeGracefulShutdownTimeOfflineOffLimit()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,                         // GracefulShutdown ::= SEQUENCE {
                  0x02, 0x02, 0x03, ( byte ) 0xE8   // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulShutdown with a delay off limit
     */
    @Test
    public void testDecodeGracefulShutdownDelayOffLimit()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x05,                     // GracefulShutdown ::= SEQUENCE {
                                                // delay INTEGER (0..86400) DEFAULT 0
                  ( byte ) 0x80, 0x03, 0x01, ( byte ) 0x86, ( byte ) 0xA0 
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulShutdown with an empty TimeOffline
     */
    @Test
    public void testDecodeGracefulShutdownTimeOfflineEmpty()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,         // GracefulShutdown ::= SEQUENCE {
                  0x02, 0x00        // timeOffline INTEGER (0..720) DEFAULT 0,
        };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }


    /**
     * Test the decoding of a GracefulShutdown with an empty delay
     */
    @Test
    public void testDecodeGracefulShutdownDelayEmpty()
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,                 // GracefulShutdown ::= SEQUENCE {
                  ( byte ) 0x80, 0x00       // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulShutdownFactory factory = ( GracefulShutdownFactory ) codec.getExtendedRequestFactories().
            get( GracefulShutdownRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( bb );
        } );
    }
}
