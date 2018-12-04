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
package org.apache.directory.api.ldap.extras.controls.syncrepl_impl;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.SynchronizationModeEnum;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncRequest.SyncRequestValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncRequest.SyncRequestValueImpl;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncRequestValueDecorator;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the SyncRequestControlValue codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SyncRequestValueControlTest extends AbstractCodecServiceTest
{
    private void testReverseEncoding( SyncRequestValue syncRequestValue, ByteBuffer bb )
    {
        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        
        SyncRequestValueFactory factory = new SyncRequestValueFactory( codec );
        factory.encodeValue( asn1Buffer, syncRequestValue );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }
    
    
    @Test
    public void testEncodeSyncRequestValue() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03, 
                  0x0A, 0x01, 0x01
            } );
        SyncRequestValue syncRequestValue = new SyncRequestValueImpl();
        syncRequestValue.setMode( SynchronizationModeEnum.REFRESH_ONLY );
        
        SyncRequestValueDecorator decorator = new SyncRequestValueDecorator( codec, syncRequestValue );
        
        ByteBuffer buffer = decorator.encode( ByteBuffer.allocate( decorator.computeLength() ) );
        
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }
    
    
    /**
     * Test the decoding of a SyncRequestValue control with a refreshOnly mode
     */
    @Test
    public void testDecodeSyncRequestValueControlRefreshOnlySuccess() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0D );
        bb.put( new byte[]
            {
                0x30, 0x0B,         // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x01, //     mode ENUMERATED {
                                    //         refreshOnly (1)
                                    //     }
                  0x04, 0x03,
                    'a', 'b', 'c',  //     cookie syncCookie OPTIONAL,
                  0x01, 0x01, 0x00  //     reloadHint BOOLEAN DEFAULT FALSE
            } );
        
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_ONLY, syncRequestValue.getMode() );
        assertEquals( "abc", Strings.utf8ToString( syncRequestValue.getCookie() ) );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                0x30, 0x08,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x01,         //     mode ENUMERATED {
                                            //         refreshOnly (1)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c'           //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with a refreshAndPersist mode
     */
    @Test
    public void testDecodeSyncRequestValueControlRefreshAndPersistSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0D );
        bb.put( new byte[]
            {
                0x30, 0x0B,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,         //     mode ENUMERATED {
                                            //         refreshAndPersist (3)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c',          //     cookie syncCookie OPTIONAL,
                  0x01, 0x01, 0x00          //     reloadHint BOOLEAN DEFAULT FALSE
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertEquals( "abc", Strings.utf8ToString( syncRequestValue.getCookie() ) );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        ByteBuffer buffer = ByteBuffer.allocate( 0x0A );
        buffer.put( new byte[]
            {
                0x30, 0x08,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,         //     mode ENUMERATED {
                                            //         refreshAndPersist (3)
                                            //     }
                  0x04, 0x03,
                    'a', 'b', 'c'           //     cookie syncCookie OPTIONAL,
            } );
        buffer.flip();

        bb = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with no cookie
     */
    @Test
    public void testDecodeSyncRequestValueControlNoCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,         //     mode ENUMERATED {
                                            //         refreshAndPersist (3)
                                            //     }
                  0x01, 0x01, 0x00          //     reloadHint BOOLEAN DEFAULT FALSE
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertNull( syncRequestValue.getCookie() );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03,             // syncRequestValue ::= SEQUENCE {
                0x0A, 0x01, 0x03,       //     mode ENUMERATED {
                                        //         refreshAndPersist (3)
                                        //     }
            } );
        bb.flip();

        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with no cookie, a true
     * reloadHint
     */
    @Test
    public void testDecodeSyncRequestValueControlNoCookieReloadHintTrue() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                0x30, 0x06,                     // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,             //     mode ENUMERATED {
                                                //         refreshAndPersist (3)
                                                //     }
                  0x01, 0x01, ( byte ) 0xFF     //     reloadHint BOOLEAN DEFAULT FALSE
        } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator )
            .decode( bb.array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertNull( syncRequestValue.getCookie() );
        assertEquals( true, syncRequestValue.isReloadHint() );

        // Check the encoding
        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with no cookie, no
     * reloadHint
     */
    @Test
    public void testDecodeSyncRequestValueControlNoCookieNoReloadHint() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03,             // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,     //     mode ENUMERATED {
                                        //         refreshAndPersist (3)
                                        //     }
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertNull( syncRequestValue.getCookie() );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with no reloadHint
     */
    @Test
    public void testDecodeSyncRequestValueControlNoReloadHintSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            {
                0x30, 0x08,             // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,     //     mode ENUMERATED {
                                        //         refreshAndPersist (3)
                                        //     }
                  0x04, 0x03,
                    'a', 'b', 'c'       //     cookie syncCookie OPTIONAL,
        } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertEquals( "abc", Strings.utf8ToString( syncRequestValue.getCookie() ) );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with an empty cookie
     */
    @Test
    public void testDecodeSyncRequestValueControlEmptyCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                0x30, 0x05,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,         //     mode ENUMERATED {
                                            //         refreshAndPersist (3)
                                            //     }
                  0x04, 0x00,               //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        SyncRequestValue syncRequestValue = ( SyncRequestValue ) ( ( SyncRequestValueDecorator ) decorator ).decode( bb
            .array() );

        assertEquals( SynchronizationModeEnum.REFRESH_AND_PERSIST, syncRequestValue.getMode() );
        assertEquals( "", Strings.utf8ToString( syncRequestValue.getCookie() ) );
        assertEquals( false, syncRequestValue.isReloadHint() );

        // Check the encoding
        bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
                0x30, 0x03,                 // syncRequestValue ::= SEQUENCE {
                  0x0A, 0x01, 0x03,         //     mode ENUMERATED {
                                            //         refreshAndPersist (3)
                                            //     }
            } );
        bb.flip();

        ByteBuffer buffer = ( ( SyncRequestValueDecorator ) syncRequestValue ).encode( ByteBuffer
            .allocate( ( ( SyncRequestValueDecorator ) syncRequestValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncRequestValue, bb );
    }


    /**
     * Test the decoding of a SyncRequestValue control with an empty sequence
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSyncRequestValueControlEmptySequence() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            {
                0x30, 0x00 // syncRequestValue ::= SEQUENCE {
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        ( ( SyncRequestValueDecorator ) decorator ).decode( bb.array() );
    }


    /**
     * Test the decoding of a SyncRequestValue control with no mode
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSyncRequestValueControlNoMode() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );
        bb.put( new byte[]
            {
                0x30, 0x05,         // syncRequestValue ::= SEQUENCE {
                  0x04, 0x03,
                    'a', 'b', 'c'   //     cookie syncCookie OPTIONAL,
            } );
        bb.flip();

        SyncRequestValue decorator = new SyncRequestValueDecorator( codec );

        ( ( SyncRequestValueDecorator ) decorator ).decode( bb.array() );
    }
}
