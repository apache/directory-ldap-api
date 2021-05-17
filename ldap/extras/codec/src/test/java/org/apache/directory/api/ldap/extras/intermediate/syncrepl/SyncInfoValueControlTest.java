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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValue;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SynchronizationInfoEnum;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl.SyncInfoValueFactory;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the SyncInfoControlValue codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SyncInfoValueControlTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerIntermediateResponse( new SyncInfoValueFactory() );
    }

    //--------------------------------------------------------------------------------
    // NewCookie choice tests
    //--------------------------------------------------------------------------------
    /**
     * Test the decoding of a SyncInfoValue control, newCookie choice
     */
    @Test
    public void testDecodeSyncInfoValueControlNewCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                ( byte ) 0x80, 0x03, // syncInfoValue ::= CHOICE {
                  'a', 'b', 'c' //     newCookie [0] syncCookie
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.NEW_COOKIE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, empty newCookie choice
     */
    @Test
    public void testDecodeSyncInfoValueControlEmptyNewCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                ( byte ) 0x80, 0x00, // syncInfoValue ::= CHOICE {
                                     //     newCookie [0] syncCookie
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.NEW_COOKIE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    //--------------------------------------------------------------------------------
    // RefreshDelete choice tests
    //--------------------------------------------------------------------------------
    /**
     * Test the decoding of a SyncInfoValue control, refreshDelete choice,
     * refreshDone = true
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshDelete() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                ( byte ) 0xA1, 0x08,        // syncInfoValue ::= CHOICE {
                                            //     refreshDelete [1] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',          //     cookie       syncCookie OPTIONAL,
                0x01, 0x01, ( byte ) 0xFF   //     refreshDone  BOOLEAN DEFAULT TRUE
        } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_DELETE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA1, 0x05, // syncInfoValue ::= CHOICE {
                                         //     refreshDelete [1] SEQUENCE {
                      0x04, 0x03,
                        'a', 'b', 'c'    //         cookie       syncCookie OPTIONAL,
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshDelete choice,
     * refreshDone = false
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshDeleteRefreshDoneFalse() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                ( byte ) 0xA1, 0x08,                // syncInfoValue ::= CHOICE {
                                                    //     refreshDelete [1] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',                  //         cookie       syncCookie OPTIONAL,
                  0x01, 0x01, ( byte ) 0x00         //         refreshDone  BOOLEAN DEFAULT TRUE
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_DELETE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshDelete choice,
     * no refreshDone
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshDeleteNoRefreshDone() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                ( byte ) 0xA1, 0x05, // syncInfoValue ::= CHOICE {
                                     //     refreshDelete [1] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c'    //         cookie       syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_DELETE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshDelete choice,
     * no cookie
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshDeleteNoCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                ( byte ) 0xA1, 0x03, // syncInfoValue ::= CHOICE {
                                     //     refreshDelete [1] SEQUENCE {
                  0x01, 0x01, 0x00   //        refreshDone  BOOLEAN DEFAULT TRUE
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_DELETE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshDelete choice,
     * no cookie, no refreshDone
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshDeleteNoCookieNoRefreshDone() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                ( byte ) 0xA1, 0x00 // syncInfoValue ::= CHOICE {
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_DELETE, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    //--------------------------------------------------------------------------------
    // RefreshPresent choice tests
    //--------------------------------------------------------------------------------
    /**
     * Test the decoding of a SyncInfoValue control, refreshPresent choice,
     * refreshDone = true
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshPresent() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                ( byte ) 0xA2, 0x08,         // syncInfoValue ::= CHOICE {
                                             //     refreshPresent [2] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',           //         cookie       syncCookie OPTIONAL,
                  0x01, 0x01, ( byte ) 0xFF  //         refreshDone  BOOLEAN DEFAULT TRUE
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_PRESENT, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA2, 0x05, // syncInfoValue ::= CHOICE {
                                         //     refreshPresent [2] SEQUENCE {
                      0x04, 0x03,
                        'a', 'b', 'c'    //         cookie       syncCookie OPTIONAL,
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshPresent choice,
     * refreshDone = false
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshPresentRefreshDoneFalse() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                ( byte ) 0xA2, 0x08,            // syncInfoValue ::= CHOICE {
                                                //     refreshPresent [2] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',              //         cookie       syncCookie OPTIONAL,
                  0x01, 0x01, ( byte ) 0x00     //         refreshDone  BOOLEAN DEFAULT TRUE
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_PRESENT, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshPresent choice,
     * no refreshDone
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshPresentNoRefreshDone() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                ( byte ) 0xA2, 0x05, // syncInfoValue ::= CHOICE {
                                     //     refreshPresent [2] SEQUENCE {
                  0x04, 0x03,
                  'a', 'b', 'c'      //         cookie       syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_PRESENT, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshPresent choice,
     * no cookie
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshPresentNoCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                ( byte ) 0xA2, 0x03, // syncInfoValue ::= CHOICE {
                                     //     refreshPresent [2] SEQUENCE {
                  0x01, 0x01, 0x00   //        refreshDone  BOOLEAN DEFAULT TRUE
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_PRESENT, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, refreshPresent choice,
     * no cookie, no refreshDone
     */
    @Test
    public void testDecodeSyncInfoValueControlRefreshPresentNoCookieNoRefreshDone() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                ( byte ) 0xA2, 0x00 // syncInfoValue ::= CHOICE {
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.REFRESH_PRESENT, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDone() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    //--------------------------------------------------------------------------------
    // syncIdSet choice tests
    //--------------------------------------------------------------------------------
    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, empty
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetEmpty() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x00, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, cookie
     * but no UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieNoSet() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x05, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',   //         cookie       syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, no cookie
     * a refreshDeletes flag, but no UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetNoCookieRefreshDeletesNoSet() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x03, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x01, 0x01, 0x00,  //         refreshDeletes BOOLEAN DEFAULT FALSE,
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, a cookie
     * a refreshDeletes flag, but no UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieRefreshDeletesNoSet() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x08, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',   //         cookie         syncCookie OPTIONAL,
                  0x01, 0x01, 0x00,  //         refreshDeletes BOOLEAN DEFAULT FALSE,
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, no cookie
     * no refreshDeletes flag, an empty UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetNoCookieNoRefreshDeletesEmptySet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x02, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x31, 0x00,        //         syncUUIDs SET OF syncUUID
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDeletes() );
        assertEquals( 0, syncInfoValue.getSyncUUIDs().size() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, no cookie
     * no refreshDeletes flag, a UUID set with some values
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetNoCookieNoRefreshDeletesUUIDsSet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x3A );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x38,        // syncInfoValue ::= CHOICE {
                                            //     syncIdSet [3] SEQUENCE {
                  0x31, 0x36,               //         syncUUIDs SET OF syncUUID
                    0x04, 0x10,             // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x04, 0x10,             // syncUUID
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x04, 0x10,             // syncUUID
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDeletes() );
        assertEquals( 3, syncInfoValue.getSyncUUIDs().size() );

        for ( int i = 0; i < 3; i++ )
        {
            byte[] uuid = syncInfoValue.getSyncUUIDs().get( i );

            for ( int j = 0; j < 16; j++ )
            {
                assertEquals( i + 1, uuid[j] );
            }
        }

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, A cookie
     * no refreshDeletes flag, an empty UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieNoRefreshDeletesEmptySet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x09 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x07, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',   //         cookie         syncCookie OPTIONAL,
                  0x31, 0x00,        //         syncUUIDs SET OF syncUUID
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDeletes() );
        assertEquals( 0, syncInfoValue.getSyncUUIDs().size() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, a cookie
     * no refreshDeletes flag, a UUID set with some values
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieNoRefreshDeletesUUIDsSet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x3F );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x3D,            // syncInfoValue ::= CHOICE {
                                                //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',              //         cookie         syncCookie OPTIONAL,
                  0x31, 0x36,                   //         syncUUIDs SET OF syncUUID
                    0x04, 0x10,                 // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x04, 0x10,                 // syncUUID
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x04, 0x10,                 // syncUUID
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertFalse( syncInfoValue.isRefreshDeletes() );
        assertEquals( 3, syncInfoValue.getSyncUUIDs().size() );

        for ( int i = 0; i < 3; i++ )
        {
            byte[] uuid = syncInfoValue.getSyncUUIDs().get( i );

            for ( int j = 0; j < 16; j++ )
            {
                assertEquals( i + 1, uuid[j] );
            }
        }

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, no cookie
     * a refreshDeletes flag, an empty UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetNoCookieRefreshDeletesEmptySet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x05, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x01, 0x01, 0x10,  //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x00,        //         syncUUIDs SET OF syncUUID
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDeletes() );
        assertEquals( 0, syncInfoValue.getSyncUUIDs().size() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA3, 0x05,         // syncInfoValue ::= CHOICE {
                                                 //     syncIdSet [3] SEQUENCE {
                      0x01, 0x01, ( byte ) 0xFF, //         refreshDeletes BOOLEAN DEFAULT FALSE,
                      0x31, 0x00,                //         syncUUIDs SET OF syncUUID
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, a cookie
     * no refreshDeletes flag, a UUID set with some values
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetNoCookieRefreshDeletesUUIDsSet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x3D );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x3B, // syncInfoValue ::= CHOICE {
                                     //     syncIdSet [3] SEQUENCE {
                  0x01, 0x01, 0x10, //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x36, //         syncUUIDs SET OF syncUUID
                    0x04, 0x10,             // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x04, 0x10,             // syncUUID
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x04, 0x10,             // syncUUID
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDeletes() );
        assertEquals( 3, syncInfoValue.getSyncUUIDs().size() );

        for ( int i = 0; i < 3; i++ )
        {
            byte[] uuid = syncInfoValue.getSyncUUIDs().get( i );

            for ( int j = 0; j < 16; j++ )
            {
                assertEquals( i + 1, uuid[j] );
            }
        }

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA3, 0x3B, // syncInfoValue ::= CHOICE {
                                         //     syncIdSet [3] SEQUENCE {
                      0x01, 0x01, ( byte ) 0xFF, //         refreshDeletes BOOLEAN DEFAULT FALSE,
                      0x31, 0x36, //         syncUUIDs SET OF syncUUID
                        0x04, 0x10,             // syncUUID
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x04, 0x10,             // syncUUID
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x04, 0x10,             // syncUUID
                          0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                          0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, a cookie
     * a refreshDeletes flag, an empty UUID set
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieRefreshDeletesEmptySet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x0A,    // syncInfoValue ::= CHOICE {
                                        //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',      //         cookie         syncCookie OPTIONAL,
                  0x01, 0x01, 0x10,     //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x00,           //         syncUUIDs SET OF syncUUID
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDeletes() );
        assertEquals( 0, syncInfoValue.getSyncUUIDs().size() );

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA3, 0x0A,            // syncInfoValue ::= CHOICE {
                                                    //     syncIdSet [3] SEQUENCE {
                      0x04, 0x03,
                        'a', 'b', 'c',              //         cookie         syncCookie OPTIONAL,
                      0x01, 0x01, ( byte ) 0xFF,    //         refreshDeletes BOOLEAN DEFAULT FALSE,
                      0x31, 0x00,                   //         syncUUIDs SET OF syncUUID
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, a cookie
     * a refreshDeletes flag, a UUID set with some values
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetCookieRefreshDeletesUUIDsSet() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x42 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x40,        // syncInfoValue ::= CHOICE {
                                            //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',          //         cookie         syncCookie OPTIONAL,
                  0x01, 0x01, 0x10,         //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x36,               //         syncUUIDs SET OF syncUUID
                    0x04, 0x10,             // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                    0x04, 0x10,             // syncUUID
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                      0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                    0x04, 0x10,             // syncUUID
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        factory.decodeValue( syncInfoValue, bb.array() );

        assertEquals( SynchronizationInfoEnum.SYNC_ID_SET, syncInfoValue.getSyncInfoValueType() );
        assertEquals( "abc", Strings.utf8ToString( syncInfoValue.getCookie() ) );
        assertTrue( syncInfoValue.isRefreshDeletes() );
        assertEquals( 3, syncInfoValue.getSyncUUIDs().size() );

        for ( int i = 0; i < 3; i++ )
        {
            byte[] uuid = syncInfoValue.getSyncUUIDs().get( i );

            for ( int j = 0; j < 16; j++ )
            {
                assertEquals( i + 1, uuid[j] );
            }
        }

        // Check the revert encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        factory.encodeValue( asn1Buffer, syncInfoValue );
        
        assertArrayEquals( 
            new byte[]
                {
                    ( byte ) 0xA3, 0x40,        // syncInfoValue ::= CHOICE {
                                                //     syncIdSet [3] SEQUENCE {
                      0x04, 0x03,
                        'a', 'b', 'c',          //         cookie         syncCookie OPTIONAL,
                      0x01, 0x01, ( byte ) 0xFF,//         refreshDeletes BOOLEAN DEFAULT FALSE,
                      0x31, 0x36,               //         syncUUIDs SET OF syncUUID
                        0x04, 0x10,             // syncUUID
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                          0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                        0x04, 0x10,             // syncUUID
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                          0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
                        0x04, 0x10,             // syncUUID
                          0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
                          0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
                }, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, with some
     * invalid UUID
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetTooSmallUUID() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x1D );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x1B,        // syncInfoValue ::= CHOICE {
                                            //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',          //         cookie         syncCookie OPTIONAL,
                  0x01, 0x01, 0x10,         //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x11,               //         syncUUIDs SET OF syncUUID
                    0x04, 0x0F,             // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }


    /**
     * Test the decoding of a SyncInfoValue control, syncIdSet choice, with some
     * invalid UUID
     */
    @Test
    public void testDecodeSyncInfoValueControlSyncIdSetTooLongUUID() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x20 );
        bb.put( new byte[]
            {
                ( byte ) 0xA3, 0x1E,        // syncInfoValue ::= CHOICE {
                                            //     syncIdSet [3] SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c',          //         cookie         syncCookie OPTIONAL,
                  0x01, 0x01, 0x10,         //         refreshDeletes BOOLEAN DEFAULT FALSE,
                  0x31, 0x13,               //         syncUUIDs SET OF syncUUID
                    0x04, 0x10,             // syncUUID
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                      0x01
            } );
        bb.flip();

        SyncInfoValueFactory factory = ( SyncInfoValueFactory ) codec.getIntermediateResponseFactories().
            get( SyncInfoValue.OID );
        SyncInfoValue syncInfoValue = factory.newResponse();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( syncInfoValue, bb.array() );
        } );
    }
}
