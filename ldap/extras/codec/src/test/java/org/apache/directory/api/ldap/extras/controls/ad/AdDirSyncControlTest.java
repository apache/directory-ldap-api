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
 * TestCase for AdDirSyncControlCodec .
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AdDirSyncControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testAdDirSyncControl() throws Exception
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

        AdDirSync decorator = new AdDirSyncDecorator( codec );

        AdDirSync adDirSync = ( AdDirSync ) ( ( AdDirSyncDecorator ) decorator ).decode( bb.array() );

        assertEquals( AdDirSyncFlag.LDAP_DIRSYNC_OBJECT_SECURITY, adDirSync.getFlag() );
        assertEquals( 0, adDirSync.getMaxReturnLength() );
        assertEquals( "xkcd", Strings.utf8ToString( adDirSync.getCookie() ) );

        // test encoding
        adDirSync.setParentFirst( 1 );
        
        try
        {
            ByteBuffer buffer = ( ( AdDirSyncDecorator ) adDirSync ).encode( ByteBuffer
                .allocate( ( ( AdDirSyncDecorator ) adDirSync ).computeLength() ) );
            String expected = "0x30 0x0C 0x02 0x01 0x01 0x02 0x01 0x00 0x04 0x04 0x78 0x6B 0x63 0x64 ";
            String decoded = Strings.dumpBytes( buffer.array() );
            assertEquals( expected, decoded );
        }
        catch ( EncoderException e )
        {
            fail( e.getMessage() );
        }
    }


    @Test
    public void testAdDirSyncControlNoCookie() throws Exception
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

        AdDirSync decorator = new AdDirSyncDecorator( codec );

        AdDirSync adDirSync = ( AdDirSync ) ( ( AdDirSyncDecorator ) decorator ).decode( bb.array() );

        assertEquals( AdDirSyncFlag.LDAP_DIRSYNC_OBJECT_SECURITY, adDirSync.getFlag() );
        assertEquals( 0, adDirSync.getMaxReturnLength() );
        assertEquals( "", Strings.utf8ToString( adDirSync.getCookie() ) );

        // test encoding
        adDirSync.setParentFirst( 1 );

        try
        {
            ByteBuffer buffer = ( ( AdDirSyncDecorator ) adDirSync ).encode( ByteBuffer
                .allocate( ( ( AdDirSyncDecorator ) adDirSync ).computeLength() ) );
            String expected = "0x30 0x08 0x02 0x01 0x01 0x02 0x01 0x00 0x04 0x00 ";
            String decoded = Strings.dumpBytes( buffer.array() );
            assertEquals( expected, decoded );
        }
        catch ( EncoderException e )
        {
            fail( e.getMessage() );
        }
    }
    
    
    @Test
    public void testAdDirSyncControlAbsentCookie() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );

        bb.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x00,  // parentFirst (false)
                  0x02, 0x01, 0x00   // maxReturnLength (no limit)
        } );

        bb.flip();

        AdDirSync decorator = new AdDirSyncDecorator( codec );

        try
        {
            ( ( AdDirSyncDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
    
    
    @Test
    public void testAdDirSyncControlAbsentParentFirst() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  0x02, 0x01, 0x00,  // maxReturnLength (no limit)
                  0x04, 0x00         // cookie
        } );

        bb.flip();

        AdDirSync decorator = new AdDirSyncDecorator( codec );

        try
        {
            ( ( AdDirSyncDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
    
    
    @Test
    public void testAdDirSyncControlEmpty() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00,
        } );

        bb.flip();

        AdDirSync decorator = new AdDirSyncDecorator( codec );

        try
        {
            ( ( AdDirSyncDecorator ) decorator ).decode( bb.array() );
            fail();
        }
        catch ( DecoderException de )
        {
            // expected
        }
    }
}
