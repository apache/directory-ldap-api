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
package org.apache.directory.api.ldap.codec.controls.sort;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Tests for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SortRequestControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeControl() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 16 );
        stream.put( new byte[]
            {
               0x30, 0x0E,
                 0x30, 0x0C,
                   0x04, 0x02,
                     'c', 'n',
                   (byte)0x80, 0x03,
                     'o', 'i', 'd',
                   (byte)0x81, 0x01, 0x00
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();
        factory.decodeValue( control, stream.array() );

        assertEquals( 1, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertEquals( "oid", sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );

        // default value of false reverseOrder will not be encoded
        Asn1Buffer buffer = new Asn1Buffer();
        factory.encodeValue( buffer, control );
        assertArrayEquals( 
            new byte[]
                {
                   0x30, 0x0B,
                     0x30, 0x09,
                       0x04, 0x02,
                         'c', 'n',
                       (byte)0x80, 0x03,
                         'o', 'i', 'd',
                }, buffer.getBytes().array() );
    }


    @Test
    public void testDecodeControlWithMultipleSortKeys() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x1E );
        stream.put( new byte[]
            {
               0x30, 0x1C,
                 0x30, 0x0C,
                   0x04, 0x02,
                     'c', 'n',
                   (byte)0x80, 0x03,
                     'o', 'i', 'd',
                   (byte)0x81, 0x01, (byte)0xFF,
                 0x30, 0x0C,
                   0x04, 0x02,
                     's', 'n',
                   (byte)0x80, 0x03,
                     'i', 'o', 'd',
                   (byte)0x81, 0x01, (byte)0xFF
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();
        factory.decodeValue( control, stream.array() );

        assertEquals( 2, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertEquals( "oid", sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );

        sk = control.getSortKeys().get( 1 );
        assertEquals( "sn", sk.getAttributeTypeDesc() );
        assertEquals( "iod", sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );

        // Check reverse encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        factory.encodeValue( buffer, control );
        
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    @Test
    public void testDecodeWithoutAtDesc() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 16 );
        stream.put( new byte[]
            {
               0x30, 0x05,
                 0x30, 0x03,
                  (byte)0x81, 0x01, 0x00
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( control, stream.array() );
        } );
    }


    @Test
    public void testDecodeControlWithoutMrOid() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0B );
        stream.put( new byte[]
            {
               0x30, 0x09,
                 0x30, 0x07,
                   0x04, 0x02,
                     'c', 'n',
                   (byte)0x81, 0x01, (byte)0xFF
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();
        factory.decodeValue( control, stream.array() );

        assertEquals( 1, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );

        // Check reverse encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        factory.encodeValue( buffer, control );
        
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    @Test
    public void testDecodeControlWithAtDescOnly() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x08 );
        stream.put( new byte[]
            {
               0x30, 0x06,
                 0x30, 0x04,
                   0x04, 0x02,
                     'c', 'n'
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();
        factory.decodeValue( control, stream.array() );

        assertEquals( 1, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );

        // Check reverse encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        factory.encodeValue( buffer, control );
        
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    @Test
    public void testDecodeControlWithMultipleAtDescOnly() throws Exception
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );
        stream.put( new byte[]
            {
               0x30, 0x0C,
                 0x30, 0x04,
                   0x04, 0x02,
                     'c', 'n',
                 0x30, 0x04,
                   0x04, 0x02,
                     's', 'n'
            } );
        stream.flip();

        SortRequestFactory factory = ( SortRequestFactory ) codec.getRequestControlFactories().get( SortRequest.OID );
        SortRequest control = factory.newControl();
        factory.decodeValue( control, stream.array() );

        assertEquals( 2, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );

        sk = control.getSortKeys().get( 1 );
        assertEquals( "sn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );

        // Check reverse encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        factory.encodeValue( buffer, control );
        
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
