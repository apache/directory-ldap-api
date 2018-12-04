/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.extras.controls.vlv;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewResponseDecorator;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewResponseFactory;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;


/**
 * VLV response control tests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VLVResponseControlTest extends AbstractCodecServiceTest
{
    @Before
    public void init()
    {
        codec.registerRequestControl( new VirtualListViewResponseFactory( codec ) );
    }

    
    @Test
    public void testDecodeFullSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x11 );

        bb.put( new byte[]
            {
                0x30, 0x0F,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x00,     //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        VirtualListViewResponse virtualListView = ( VirtualListViewResponse ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getTargetPosition() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertEquals( VirtualListViewResultCode.SUCCESS, virtualListView.getVirtualListViewResult() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        // Test encoding
        ByteBuffer encoded = ( ( VirtualListViewResponseDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewResponseDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
        
        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        VirtualListViewResponseFactory factory = ( VirtualListViewResponseFactory ) codec.getRequestControlFactories().get( VirtualListViewResponse.OID );
        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }

    
    @Test
    public void testDecodeFullSuccessEmptyContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0D );

        bb.put( new byte[]
            {
                0x30, 0x0B,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x00,     //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
                  0x04, 0x00            //    contextID     OCTET STRING OPTIONAL }
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        VirtualListViewResponse virtualListView = ( VirtualListViewResponse ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getTargetPosition() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertEquals( VirtualListViewResultCode.SUCCESS, virtualListView.getVirtualListViewResult() );
        assertEquals( "", Strings.utf8ToString( virtualListView.getContextId() ) );

        // Test encoding
        bb = ByteBuffer.allocate( 0x0B );

        bb.put( new byte[]
            {
                0x30, 0x09,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x00      //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
            } );

        ByteBuffer encoded = ( ( VirtualListViewResponseDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewResponseDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
        
        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        VirtualListViewResponseFactory factory = ( VirtualListViewResponseFactory ) codec.getRequestControlFactories().get( VirtualListViewResponse.OID );
        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }

    
    @Test
    public void testDecodeFullSuccessNoContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0B );

        bb.put( new byte[]
            {
                0x30, 0x09,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x00      //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        VirtualListViewResponse virtualListView = ( VirtualListViewResponse ) control.decode( bb.array() );

        assertEquals( 1, virtualListView.getTargetPosition() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertEquals( VirtualListViewResultCode.SUCCESS, virtualListView.getVirtualListViewResult() );

        // Test encoding
        ByteBuffer encoded = ( ( VirtualListViewResponseDecorator ) virtualListView ).encode(
            ByteBuffer.allocate( ( ( VirtualListViewResponseDecorator ) virtualListView ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
        
        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        VirtualListViewResponseFactory factory = ( VirtualListViewResponseFactory ) codec.getRequestControlFactories().get( VirtualListViewResponse.OID );
        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }

    
    @Test( expected=IllegalArgumentException.class )
    public void testDecodeFullBadResult() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x11 );

        bb.put( new byte[]
            {
                0x30, 0x0F,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x11,     //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        control.decode( bb.array() );
    }

    
    @Test( expected=DecoderException.class )
    public void testDecodeEmptyVLVResponse() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );

        bb.put( new byte[]
            {
                0x30, 0x00              // VirtualListViewResponse ::= SEQUENCE {
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        control.decode( bb.array() );
    }

    
    @Test( expected=DecoderException.class )
    public void testDecodeNoTargetPositionVLVResponse() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x0A, 0x01, 0x00,     //    virtualListViewResult ENUMERATED {
                                        //                   success (0),
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        control.decode( bb.array() );
    }

    
    @Test( expected=DecoderException.class )
    public void testDecodeNoResultVLVResponse() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,             // VirtualListViewResponse ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    targetPosition    INTEGER (0 .. maxInt),
                  0x02, 0x01, 0x01,     //    contentCount     INTEGER (0 .. maxInt),
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        // Test decoding
        VirtualListViewResponseDecorator control = new VirtualListViewResponseDecorator( codec );
        control.decode( bb.array() );
    }
}
