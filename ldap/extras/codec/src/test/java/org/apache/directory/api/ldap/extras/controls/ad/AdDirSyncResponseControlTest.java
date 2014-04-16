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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * 
 * TestCase for AdDirSyncResponseControlCodec .
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AdDirSyncResponseControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testAdDirSyncResponseControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,
                  0x02, 0x01, 0x01,  // flag (LDAP_DIRSYNC_OBJECT_SECURITY)
                  0x02, 0x01, 0x00,  // maxReturnLength (no limit)
                  0x04, 0x04, 'x', 'k', 'c', 'd' // the cookie 
        } );

        bb.flip();

        AdDirSyncResponse decorator = new AdDirSyncResponseDecorator( codec );

        AdDirSyncResponse adDirSyncResponse = ( AdDirSyncResponse ) ( ( AdDirSyncResponseDecorator ) decorator ).decode( bb.array() );

        assertEquals( AdDirSyncFlag.LDAP_DIRSYNC_OBJECT_SECURITY, adDirSyncResponse.getFlag() );
        assertEquals( 0, adDirSyncResponse.getMaxReturnLength() );
        assertEquals( "xkcd", Strings.utf8ToString( adDirSyncResponse.getCookie() ) );

        // test encoding
        try
        {
            ByteBuffer buffer = ( ( AdDirSyncResponseDecorator ) adDirSyncResponse ).encode( ByteBuffer
                .allocate( ( ( AdDirSyncResponseDecorator ) adDirSyncResponse ).computeLength() ) );
            String expected = Strings.dumpBytes( bb.array() );
            String decoded = Strings.dumpBytes( buffer.array() );
            assertEquals( expected, decoded );
        }
        catch ( EncoderException e )
        {
            fail( e.getMessage() );
        }
    }


    @Test
    public void testAdDirSyncResponseControlNoCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );

        bb.put( new byte[]
            {
                0x30, 0x08,
                  0x02, 0x01, 0x01,  // flag (LDAP_DIRSYNC_OBJECT_SECURITY)
                  0x02, 0x01, 0x00,  // maxReturnLength (no limit)
                  0x04, 0x00         // the cookie 
        } );

        bb.flip();

        AdDirSyncResponse decorator = new AdDirSyncResponseDecorator( codec );

        AdDirSyncResponse adDirSyncResponse = ( AdDirSyncResponse ) ( ( AdDirSyncResponseDecorator ) decorator ).decode( bb.array() );

        assertEquals( AdDirSyncFlag.LDAP_DIRSYNC_OBJECT_SECURITY, adDirSyncResponse.getFlag() );
        assertEquals( 0, adDirSyncResponse.getMaxReturnLength() );
        assertEquals( "", Strings.utf8ToString( adDirSyncResponse.getCookie() ) );

        // test encoding
        try
        {
            ByteBuffer buffer = ( ( AdDirSyncResponseDecorator ) adDirSyncResponse ).encode( ByteBuffer
                .allocate( ( ( AdDirSyncResponseDecorator ) adDirSyncResponse ).computeLength() ) );
            String expected = Strings.dumpBytes( bb.array() );
            String decoded = Strings.dumpBytes( buffer.array() );
            assertEquals( expected, decoded );
        }
        catch ( EncoderException e )
        {
            fail( e.getMessage() );
        }
    }
    
    
    @Test
    public void testAdDirSyncResponseControlAbsentCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );

        bb.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x01,  // parentFirst (LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER)
                  0x02, 0x01, 0x00   // maxReturnLength (no limit)
        } );

        bb.flip();

        AdDirSyncResponse decorator = new AdDirSyncResponseDecorator( codec );

        try
        {
            ( ( AdDirSyncResponseDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
    
    
    @Test
    public void testAdDirSyncResponseControlAbsentParentFirst() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  0x02, 0x01, 0x00,  // maxReturnLength (no limit)
                  0x04, 0x00         // cookie
        } );

        bb.flip();

        AdDirSyncResponse decorator = new AdDirSyncResponseDecorator( codec );

        try
        {
            ( ( AdDirSyncResponseDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
    
    
    @Test
    public void testAdDirSyncResponseControlEmpty() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00,
        } );

        bb.flip();

        AdDirSyncResponse decorator = new AdDirSyncResponseDecorator( codec );

        try
        {
            ( ( AdDirSyncResponseDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
}
