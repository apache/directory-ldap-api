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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateTypeEnum;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncState.SyncStateValue;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the SyncStateControlValue codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SyncStateValueControlTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerResponseControl( new SyncStateValueFactory( codec ) );
    }
    
    
    private void testReverseEncoding( SyncStateValue syncStateValue, SyncStateValueFactory factory, ByteBuffer bb )
    {
        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        
        factory.encodeValue( asn1Buffer, syncStateValue );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }
    
    
    /**
     * Test the decoding of a SyncStateValue control with a refreshOnly mode
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSyncStateValueControlWithStateType() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 16 );
        bb.put( new byte[]
            {
                0x30, 0x0E,                 // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x00,         //     state ENUMERATED {
                                            //         present (0)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c',          //     entryUUID syncUUID OPTIONAL,
                  0x04, 0x04,
                    'x', 'k', 'c', 'd'      //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        factory.decodeValue( syncStateValue, bb.array() );

        assertEquals( SyncStateTypeEnum.PRESENT, syncStateValue.getSyncStateType() );
        assertEquals( "abc", Strings.utf8ToString( syncStateValue.getEntryUUID() ) );
        assertEquals( "xkcd", Strings.utf8ToString( syncStateValue.getCookie() ) );

        // Test reverse encoding
        testReverseEncoding( syncStateValue, factory, bb );
    }


    /**
     * Test the decoding of a SyncStateValue control with no cookie
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSyncStateValueControlNoCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 10 );
        bb.put( new byte[]
            { 
                0x30, 0x08,                 // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x01,         //     state ENUMERATED {
                                            //         add (1)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c',          //     entryUUID syncUUID OPTIONAL,
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        factory.decodeValue( syncStateValue, bb.array() );

        assertEquals( SyncStateTypeEnum.ADD, syncStateValue.getSyncStateType() );
        assertEquals( "abc", Strings.utf8ToString( syncStateValue.getEntryUUID() ) );
        assertNull( syncStateValue.getCookie() );

        // Test reverse encoding
        testReverseEncoding( syncStateValue, factory, bb );
    }


    /**
     * Test the decoding of a SyncStateValue control with an empty cookie
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSyncStateValueControlEmptyCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                0x30, 0x0A,             // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x02,     //     state ENUMERATED {
                                        //         modify (2)
                                        //     }
                  0x04, 0x03,
                    'a', 'b', 'c',      //     entryUUID syncUUID OPTIONAL,
                  0x04, 0x00            //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        factory.decodeValue( syncStateValue, bb.array() );

        assertEquals( SyncStateTypeEnum.MODIFY, syncStateValue.getSyncStateType() );
        assertEquals( "abc", Strings.utf8ToString( syncStateValue.getEntryUUID() ) );
        assertEquals( "", Strings.utf8ToString( syncStateValue.getCookie() ) );

        // Check the encoding
        bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 
                0x30, 0x08,             // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x02,     //     state ENUMERATED {
                                        //         modify (2)
                                        //     }
                  0x04, 0x03,
                    'a', 'b', 'c',      //     entryUUID syncUUID OPTIONAL,
            } );
        bb.flip();

        // Test reverse encoding
        testReverseEncoding( syncStateValue, factory, bb );
    }


    /**
     * Test the decoding of a SyncStateValue control with an empty sequence
     */
    @Test
    public void testDecodeSyncStateValueControlEmptySequence()
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                0x30, 0x00 // SyncStateValue ::= SEQUENCE {
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncStateValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncStateValue control with no syncState
     */
    @Test
    public void testDecodeSyncStateValueControlNoSyancState()
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                0x30, 0x05,             // SyncStateValue ::= SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',      //     entryUUID syncUUID OPTIONAL,
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncStateValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncStateValue control with no syncUUID
     */
    @Test
    public void testDecodeSyncStateValueControlNoSyncUUID()
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03,             // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x02,     //     state ENUMERATED {
                                        //         modify (2)
                                        //     }
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncStateValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncStateValue control with a refreshOnly mode
     * and MODDN state type
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSyncStateValueControlWithModDnStateType() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 16 );
        bb.put( new byte[]
            {
                0x30, 0x0E,                 // SyncStateValue ::= SEQUENCE {
                  0x0A, 0x01, 0x04,         //     state ENUMERATED {
                                            //         present (0)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c',          //     entryUUID syncUUID OPTIONAL,
                  0x04, 0x04,
                    'x', 'k', 'c', 'd'      //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncStateValueFactory factory = ( SyncStateValueFactory ) codec.getResponseControlFactories().
            get( SyncStateValue.OID );
        SyncStateValue syncStateValue = factory.newControl();
        factory.decodeValue( syncStateValue, bb.array() );

        assertEquals( SyncStateTypeEnum.MODDN, syncStateValue.getSyncStateType() );
        assertEquals( "abc", Strings.utf8ToString( syncStateValue.getEntryUUID() ) );
        assertEquals( "xkcd", Strings.utf8ToString( syncStateValue.getCookie() ) );

        // Test reverse encoding
        testReverseEncoding( syncStateValue, factory, bb );
    }
}
