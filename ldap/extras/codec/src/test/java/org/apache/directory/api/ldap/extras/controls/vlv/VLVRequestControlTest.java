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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.controls.vlv_impl.VirtualListViewRequestFactory;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * VLV request control tests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class VLVRequestControlTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerRequestControl( new VirtualListViewRequestFactory( codec ) );
    }

    
    @Test
    public void testDecodeOffsetWithContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x16 );

        bb.put( new byte[]
            {
                0x30, 0x14,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                    0x02, 0x01, 0x01,   //                        contentCount    INTEGER (0 .. maxInt) },
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        // Test decoding
        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeOffsetWithoutContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                    0x02, 0x01, 0x01,   //                        contentCount    INTEGER (0 .. maxInt) },
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertNull( virtualListView.getContextId() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeOffsetEmptyContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x12 );

        bb.put( new byte[]
            {
                0x30, 0x10,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                    0x02, 0x01, 0x01,   //                        contentCount    INTEGER (0 .. maxInt) },
                    0x04, 0x00          //    contextID     OCTET STRING OPTIONAL }
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasOffset() );
        assertEquals( 1, virtualListView.getOffset() );
        assertEquals( 1, virtualListView.getContentCount() );
        assertNull( virtualListView.getContextId() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( 
            new byte[]
                {
                    0x30, 0x0E,             // VirtualListViewRequest ::= SEQUENCE {
                      0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                      0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                      ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                            //                   byOffset        [0] SEQUENCE {
                        0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                        0x02, 0x01, 0x01    //                        contentCount    INTEGER (0 .. maxInt) },
                },  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeAssertionValueWithContextID() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );

        bb.put( new byte[]
            {
                0x30, 0x12,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                                        //        target       CHOICE {
                  ( byte ) 0x81, 0x04,  //              greaterThanOrEqual [1] AssertionValue },
                    'a', 'b', 'c', 'd',
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
        } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeAssertionValueEmptyContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,                 // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,         //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,         //    afterCount     INTEGER (0..maxInt),
                                            //        target       CHOICE {
                  ( byte ) 0x81, 0x04,      //              greaterThanOrEqual [1] AssertionValue },
                      'a', 'b', 'c', 'd',
                  0x04, 0x00                //    contextID     OCTET STRING OPTIONAL }
        } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertNull( virtualListView.getContextId() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( 
            new byte[]
                {
                    0x30, 0x0C,                 // VirtualListViewRequest ::= SEQUENCE {
                      0x02, 0x01, 0x01,         //    beforeCount    INTEGER (0..maxInt),
                      0x02, 0x01, 0x01,         //    afterCount     INTEGER (0..maxInt),
                                                //        target       CHOICE {
                      ( byte ) 0x81, 0x04,      //              greaterThanOrEqual [1] AssertionValue },
                          'a', 'b', 'c', 'd'
            },  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeAssertionValueWithoutContextID() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,                 // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,         //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,         //    afterCount     INTEGER (0..maxInt),
                                            //        target       CHOICE {
                  ( byte ) 0x81, 0x04,      //              greaterThanOrEqual [1] AssertionValue },
                      'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertNull( virtualListView.getContextId() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeEmptySequence() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x2 );

        bb.put( new byte[]
            {
                0x30, 0x00
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }


    @Test
    public void testDecodeNoBeforeCount() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x13 );

        bb.put( new byte[]
            {
                0x30, 0x11,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                    0x02, 0x01, 0x01,   //                        contentCount    INTEGER (0 .. maxInt) },
                    0x04, 0x04,         //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }


    @Test
    public void testDecodeNoTarget() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );

        bb.put( new byte[]
            {
                0x30, 0x0C,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount     INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                  'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }


    @Test
    public void testDecodeEmptyByOffset() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount     INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x00,  //    target       CHOICE {
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }


    @Test
    public void testDecodeEmptyAssertionValue() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );

        bb.put( new byte[]
            {
                0x30, 0x0E,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount     INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0x81, 0x00,  //    greaterThanOrEqual [1] AssertionValue },
                  0x04, 0x04,           //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        factory.decodeValue( virtualListView, bb.array() );

        assertEquals( 1, virtualListView.getBeforeCount() );
        assertEquals( 1, virtualListView.getAfterCount() );
        assertTrue( virtualListView.hasAssertionValue() );
        assertEquals( "", Strings.utf8ToString( virtualListView.getAssertionValue() ) );
        assertEquals( "abcd", Strings.utf8ToString( virtualListView.getContextId() ) );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, virtualListView );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeByOffsetNoOffsetOrContentCount() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x13 );

        bb.put( new byte[]
            {
                0x30, 0x11,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x03,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x01,   //                        offset          INTEGER (1 .. maxInt),
                    0x04, 0x04,         //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }


    @Test
    public void testDecodeByOffsetWrongOffset() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x16 );

        bb.put( new byte[]
            {
                0x30, 0x14,             // VirtualListViewRequest ::= SEQUENCE {
                  0x02, 0x01, 0x01,     //    beforeCount    INTEGER (0..maxInt),
                  0x02, 0x01, 0x01,     //    afterCount     INTEGER (0..maxInt),
                  ( byte ) 0xA0, 0x06,  //    target       CHOICE {
                                        //                   byOffset        [0] SEQUENCE {
                    0x02, 0x01, 0x00,   //                        offset          INTEGER (1 .. maxInt),
                    0x02, 0x01, 0x01,   //                        contentCount    INTEGER (0 .. maxInt) },
                    0x04, 0x04,         //    contextID     OCTET STRING OPTIONAL }
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        VirtualListViewRequestFactory factory = ( VirtualListViewRequestFactory ) codec.getRequestControlFactories().
            get( VirtualListViewRequest.OID );
        VirtualListViewRequest virtualListView = factory.newControl();
        
        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( virtualListView, bb.array() );
        } );
    }
}
