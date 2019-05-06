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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.EnumSet;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.ad_impl.AdDirSyncResponseFactory;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 *
 * TestCase for AdDirSyncControlCodec .
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class AdDirSyncResponseControlTest extends AbstractCodecServiceTest
{
    @BeforeEach
    public void init()
    {
        codec.registerResponseControl( new AdDirSyncResponseFactory( codec ) );
    }
    
    
    @Test
    public void testAdDirSyncControl() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0F );

        bb.put( new byte[]
            {
                0x30, 0x0D,
                  0x02, 0x02, 0x08, 0x01,   // flag (LDAP_DIRSYNC_OBJECT_SECURITY, LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER)
                  0x02, 0x01, 0x00,         // maxReturnLength (no limit)
                  0x04, 0x04,
                    'x', 'k', 'c', 'd'      // the cookie
            } );

        bb.flip();

        AdDirSyncResponseFactory factory = ( AdDirSyncResponseFactory ) codec.getResponseControlFactories().
            get( AdDirSyncResponse.OID );
        AdDirSyncResponse adDirSyncResponse = factory.newControl();
        factory.decodeValue( adDirSyncResponse, bb.array() );

        assertEquals( EnumSet.of(
            AdDirSyncResponseFlag.LDAP_DIRSYNC_OBJECT_SECURITY,
            AdDirSyncResponseFlag.LDAP_DIRSYNC_ANCESTORS_FIRST_ORDER ),
            adDirSyncResponse.getFlags() );
        assertEquals( 0, adDirSyncResponse.getMaxReturnLength() );
        assertEquals( "xkcd", Strings.utf8ToString( adDirSyncResponse.getCookie() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, adDirSyncResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testAdDirSyncControlNoCookie() throws DecoderException, EncoderException
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

        AdDirSyncResponseFactory factory = ( AdDirSyncResponseFactory ) codec.getResponseControlFactories().
            get( AdDirSyncResponse.OID );
        AdDirSyncResponse adDirSyncResponse = factory.newControl();
        factory.decodeValue( adDirSyncResponse, bb.array() );

        assertEquals( EnumSet.of( AdDirSyncResponseFlag.LDAP_DIRSYNC_OBJECT_SECURITY ), adDirSyncResponse.getFlags() );
        assertEquals( 0, adDirSyncResponse.getMaxReturnLength() );
        assertEquals( "", Strings.utf8ToString( adDirSyncResponse.getCookie() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, adDirSyncResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testAdDirSyncControlAbsentCookie() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );

        bb.put( new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x00,  // parentFirst (false)
                  0x02, 0x01, 0x00   // maxReturnLength (no limit)
            } );

        bb.flip();

        AdDirSyncResponseFactory factory = ( AdDirSyncResponseFactory ) codec.getResponseControlFactories().
            get( AdDirSyncResponse.OID );
        AdDirSyncResponse adDirSyncResponse = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( adDirSyncResponse, bb.array() );
        } );
    }


    @Test
    public void testAdDirSyncControlAbsentParentFirst() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x07 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  0x02, 0x01, 0x00,  // maxReturnLength (no limit)
                  0x04, 0x00         // cookie
            } );

        bb.flip();

        AdDirSyncResponseFactory factory = ( AdDirSyncResponseFactory ) codec.getResponseControlFactories().
            get( AdDirSyncResponse.OID );
        AdDirSyncResponse adDirSyncResponse = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( adDirSyncResponse, bb.array() );
        } );
    }


    @Test
    public void testAdDirSyncControlEmpty() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00,
            } );

        bb.flip();

        AdDirSyncResponseFactory factory = ( AdDirSyncResponseFactory ) codec.getResponseControlFactories().
            get( AdDirSyncResponse.OID );
        AdDirSyncResponse adDirSyncResponse = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( adDirSyncResponse, bb.array() );
        } );
    }
}
