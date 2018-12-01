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
package org.apache.directory.api.ldap.extras.controls.ad;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncRequestDecorator;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncRequestFactory;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 *
 * TestCase for AdDirSyncRequestControlCodec .
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AdDirSyncRequestControlTest extends AbstractCodecServiceTest
{
    @Before
    public void init()
    {
        codec.registerRequestControl( new AdDirSyncRequestFactory( codec ) );
    }
    @Test
    public void testAdDirSyncRequestControl() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0F );

        bb.put( new byte[]
            {
                0x30, 0x0C,
                  0x02, 0x01, 0x01,         // parentsFirst
                  0x02, 0x01, 0x00,         // maxAttributeCount (no limit)
                  0x04, 0x04,
                    'x', 'k', 'c', 'd'      // the cookie
            } );

        bb.flip();

        AdDirSyncRequest decorator = new AdDirSyncRequestDecorator( codec );

        AdDirSyncRequest adDirSync = ( AdDirSyncRequest ) ( ( AdDirSyncRequestDecorator ) decorator ).decode( bb.array() );

        assertEquals( 1, adDirSync.getParentsFirst() );
        assertEquals( 0, adDirSync.getMaxAttributeCount() );
        assertEquals( "xkcd", Strings.utf8ToString( adDirSync.getCookie() ) );

        // test encoding
        ByteBuffer buffer = ( ( AdDirSyncRequestDecorator ) adDirSync ).encode( ByteBuffer
            .allocate( ( ( AdDirSyncRequestDecorator ) adDirSync ).computeLength() ) );
        String expected = "0x30 0x0C 0x02 0x01 0x01 0x02 0x01 0x00 0x04 0x04 0x78 0x6B 0x63 0x64 ";
        String decoded = Strings.dumpBytes( buffer.array() );
        assertEquals( expected, decoded );
    }


    @Test
    public void testAdDirSyncControlNoCookie() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );

        bb.put( new byte[]
            {
                0x30, 0x08,
                  0x02, 0x01, 0x01,  // parentsFirst
                  0x02, 0x01, 0x00,  // maxAttributeCount (no limit)
                  0x04, 0x00         // the cookie
            } );

        bb.flip();

        AdDirSyncRequest decorator = new AdDirSyncRequestDecorator( codec );

        AdDirSyncRequest adDirSync = ( AdDirSyncRequest ) ( ( AdDirSyncRequestDecorator ) decorator ).decode( bb.array() );

        assertEquals( 1, adDirSync.getParentsFirst() );
        assertEquals( 0, adDirSync.getMaxAttributeCount() );
        assertEquals( "", Strings.utf8ToString( adDirSync.getCookie() ) );

        // test encoding
        ByteBuffer buffer = ( ( AdDirSyncRequestDecorator ) adDirSync ).encode( ByteBuffer
            .allocate( ( ( AdDirSyncRequestDecorator ) adDirSync ).computeLength() ) );
        String expected = "0x30 0x08 0x02 0x01 0x01 0x02 0x01 0x00 0x04 0x00 ";
        String decoded = Strings.dumpBytes( buffer.array() );
        assertEquals( expected, decoded );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        AdDirSyncRequestFactory factory = ( AdDirSyncRequestFactory ) codec.getRequestControlFactories().get( AdDirSyncRequest.OID );
        factory.encodeValue( asn1Buffer, adDirSync );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test( expected=DecoderException.class )
    public void testAdDirSyncControlAbsentCookie() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );

        bb.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x00,  // parentsFirst
                  0x02, 0x01, 0x00   // maxAttributeCount (no limit)
            } );

        bb.flip();

        AdDirSyncRequest decorator = new AdDirSyncRequestDecorator( codec );

        ( ( AdDirSyncRequestDecorator ) decorator ).decode( bb.array() );
    }


    @Test( expected=DecoderException.class )
    public void testAdDirSyncControlAbsentParentFirst() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  0x02, 0x01, 0x00,  // maxAttributeCount (no limit)
                  0x04, 0x00         // cookie
            } );

        bb.flip();

        AdDirSyncRequest decorator = new AdDirSyncRequestDecorator( codec );

        ( ( AdDirSyncRequestDecorator ) decorator ).decode( bb.array() );
    }


    @Test( expected=DecoderException.class )
    public void testAdDirSyncControlEmpty() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00,
            } );

        bb.flip();

        AdDirSyncRequest decorator = new AdDirSyncRequestDecorator( codec );

        ( ( AdDirSyncRequestDecorator ) decorator ).decode( bb.array() );
    }
}
