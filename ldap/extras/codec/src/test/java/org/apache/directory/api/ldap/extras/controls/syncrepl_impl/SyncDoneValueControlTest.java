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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.syncrepl.syncDone.SyncDoneValue;
import org.apache.directory.api.ldap.extras.controls.syncrepl_impl.SyncDoneValueDecorator;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * 
 * TestCase for SyncDoneValueControlCodec .
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SyncDoneValueControlTest extends AbstractCodecServiceTest
{
    private void testReverseEncoding( SyncDoneValue syncDoneValue, ByteBuffer bb )
    {
        // Test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        
        SyncDoneValueFactory factory = new SyncDoneValueFactory( codec );
        factory.encodeValue( asn1Buffer, syncDoneValue );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }
    
    
    @Test
    public void testSyncDoneValueControl() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 11 );

        bb.put( new byte[]
            {
                0x30, 0x09,
                  0x04, 0x04, 'x', 'k', 'c', 'd',   // the cookie 
                  0x01, 0x01, ( byte ) 0xFF         // refreshDeletes flag TRUE
            } );

        bb.flip();

        SyncDoneValue decorator = new SyncDoneValueDecorator( codec );

        SyncDoneValue syncDoneValue = ( SyncDoneValue ) ( ( SyncDoneValueDecorator ) decorator ).decode( bb.array() );

        assertEquals( "xkcd", Strings.utf8ToString( syncDoneValue.getCookie() ) );
        assertTrue( syncDoneValue.isRefreshDeletes() );

        // test encoding
        ByteBuffer buffer = ( ( SyncDoneValueDecorator ) syncDoneValue ).encode( ByteBuffer
            .allocate( ( ( SyncDoneValueDecorator ) syncDoneValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncDoneValue, bb );
    }


    @Test
    public void testSyncDoneValueControlWithoutCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 5 );

        bb.put( new byte[]
            {
                0x30, 0x03,
                                            // null cookie
                  0x01, 0x01, ( byte ) 0xFF // refreshDeletes flag TRUE
            } );

        bb.flip();

        SyncDoneValue decorator = new SyncDoneValueDecorator( codec );

        SyncDoneValue syncDoneValue = ( SyncDoneValue ) ( ( SyncDoneValueDecorator ) decorator ).decode( bb.array() );

        assertNull( syncDoneValue.getCookie() );
        assertTrue( syncDoneValue.isRefreshDeletes() );

        // test encoding
        ByteBuffer buffer = ( ( SyncDoneValueDecorator ) syncDoneValue ).encode( ByteBuffer
            .allocate( ( ( SyncDoneValueDecorator ) syncDoneValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncDoneValue, bb );
    }


    @Test
    public void testSyncDoneValueWithSequenceOnly() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 2 );

        bb.put( new byte[]
            {
                0x30, 0x00
            } );

        bb.flip();

        SyncDoneValue decorator = new SyncDoneValueDecorator( codec );

        SyncDoneValue syncDoneValue = ( SyncDoneValue ) ( ( SyncDoneValueDecorator ) decorator ).decode( bb.array() );

        assertNull( syncDoneValue.getCookie() );
        assertFalse( syncDoneValue.isRefreshDeletes() );
        
        // Test reverse encoding
        testReverseEncoding( syncDoneValue, bb );
    }


    @Test
    public void testSyncDoneValueControlWithEmptyCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 7 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  0x04, 0x00,         // empty cookie
                  0x01, 0x01, 0x00    // refreshDeletes flag FALSE
            } );

        bb.flip();

        SyncDoneValue decorator = new SyncDoneValueDecorator( codec );

        SyncDoneValue syncDoneValue = ( SyncDoneValue ) ( ( SyncDoneValueDecorator ) decorator ).decode( bb.array() );

        assertEquals( "", Strings.utf8ToString( syncDoneValue.getCookie() ) );
        assertFalse( syncDoneValue.isRefreshDeletes() );

        // test encoding
        bb = ByteBuffer.allocate( 2 );

        bb.put( new byte[]
            {
                0x30, 0x00
            }); 

       ByteBuffer buffer = ( ( SyncDoneValueDecorator ) syncDoneValue ).encode( ByteBuffer
            .allocate( ( ( SyncDoneValueDecorator ) syncDoneValue ).computeLength() ) );
        assertArrayEquals( bb.array(), buffer.array() );
        
        // Test reverse encoding
        testReverseEncoding( syncDoneValue, bb );
    }
}
