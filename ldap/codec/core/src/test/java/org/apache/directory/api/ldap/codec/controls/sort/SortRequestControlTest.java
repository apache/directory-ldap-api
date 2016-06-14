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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.junit.Test;

/**
 * Tests for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortRequestControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeControl() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 16 );
        buffer.put( new byte[]
            {
               0x30, 0x0E,
                0x30, 0x0C,
                   0x04, 0x02, 'c', 'n',
                   (byte)0x80, 0x03, 'o', 'i', 'd',
                   (byte)0x81, 0x01, 0x00
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        SortRequest control = ( SortRequest ) decorator.decode( buffer.array() );
        
        assertEquals( 1, control.getSortKeys().size() );
        
        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertEquals( "oid", sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );
        
        // default value of false reverseOrder will not be encoded
        int skipBytes = 3;
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() - skipBytes );
        decorator.computeLength();
        decorator.encode( encoded );
        assertFalse( Arrays.equals( buffer.array(), encoded.array() ) );
        assertEquals( buffer.array().length - skipBytes, encoded.array().length );
    }
    
    
    @Test
    public void testDecodeControlWithMultipleSortKeys() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 0x1E );
        buffer.put( new byte[]
            {
               0x30, 0x1C,

                0x30, 0x0C,
                   0x04, 0x02, 'c', 'n',
                   (byte)0x80, 0x03, 'o', 'i', 'd',
                   (byte)0x81, 0x01, (byte)0xFF,

                0x30, 0x0C,
                   0x04, 0x02, 's', 'n',
                   (byte)0x80, 0x03, 'i', 'o', 'd',
                   (byte)0x81, 0x01, (byte)0xFF
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        SortRequest control = ( SortRequest ) decorator.decode( buffer.array() );
        
        assertEquals( 2, control.getSortKeys().size() );

        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertEquals( "oid", sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );
        
        sk = control.getSortKeys().get( 1 );
        assertEquals( "sn", sk.getAttributeTypeDesc() );
        assertEquals( "iod", sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }

    
    @Test(expected = DecoderException.class)
    public void testDecodeWithoutAtDesc() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 7 );
        buffer.put( new byte[]
            {
               0x30, 0x05,
                0x30, 0x03,
                (byte)0x81, 0x01, 0x00
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        decorator.decode( buffer.array() );
    }
    
    
    @Test
    public void testDecodeControlWithoutMrOid() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 11 );
        buffer.put( new byte[]
            {
               0x30, 0x09,
                0x30, 0x07,
                   0x04, 0x02, 'c', 'n',
                   (byte)0x81, 0x01, (byte)0xFF
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        SortRequest control = ( SortRequest ) decorator.decode( buffer.array() );
        
        assertEquals( 1, control.getSortKeys().size() );
        
        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertTrue( sk.isReverseOrder() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }
    
    
    @Test
    public void testDecodeControlWithAtDescOnly() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 8 );
        buffer.put( new byte[]
            {
               0x30, 0x06,
                0x30, 0x04,
                0x04, 0x02, 'c', 'n'
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        SortRequest control = ( SortRequest ) decorator.decode( buffer.array() );
        
        assertEquals( 1, control.getSortKeys().size() );
        
        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }

    
    @Test
    public void testDecodeControlWithMultipleAtDescOnly() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 0x0E );
        buffer.put( new byte[]
            {
               0x30, 0x0C,
                0x30, 0x04,
                 0x04, 0x02, 'c', 'n',
                0x30, 0x04,
                 0x04, 0x02, 's', 'n'
            } );
        buffer.flip();
        
        SortRequestDecorator decorator = new SortRequestDecorator( codec );
        SortRequest control = ( SortRequest ) decorator.decode( buffer.array() );
        
        assertEquals( 2, control.getSortKeys().size() );
        
        SortKey sk = control.getSortKeys().get( 0 );
        assertEquals( "cn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );
        
        sk = control.getSortKeys().get( 1 );
        assertEquals( "sn", sk.getAttributeTypeDesc() );
        assertNull( sk.getMatchingRuleId() );
        assertFalse( sk.isReverseOrder() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }

}
