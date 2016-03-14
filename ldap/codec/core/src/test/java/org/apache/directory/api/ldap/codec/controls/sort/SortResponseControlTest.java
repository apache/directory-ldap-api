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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.directory.api.ldap.codec.controls.sort.SortResponseDecorator;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.SortResultCode;
import org.junit.Test;

/**
 * Tests for SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortResponseControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeControl() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 0x09 );
        buffer.put( new byte[]
            {
               0x30, 0x07,
                0x0A, 0x01, 0x00,
                0x04, 0x02, 'c', 'n'
            } );
        buffer.flip();
        
        SortResponseDecorator decorator = new SortResponseDecorator( codec );
        SortResponse control = ( SortResponse ) decorator.decode( buffer.array() );
        
        assertEquals( SortResultCode.SUCCESS, control.getSortResult() );
        assertEquals( "cn", control.getAttributeName() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }

    
    @Test
    public void testDecodeControlWithoutAtType() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 0x05 );
        buffer.put( new byte[]
            {
               0x30, 0x03,
                0x0A, 0x01, 0x10
            } );
        buffer.flip();
        
        SortResponseDecorator decorator = new SortResponseDecorator( codec );
        SortResponse control = ( SortResponse ) decorator.decode( buffer.array() );
        
        assertEquals( SortResultCode.NOSUCHATTRIBUTE, control.getSortResult() );
        assertNull( control.getAttributeName() );
        
        ByteBuffer encoded = ByteBuffer.allocate( buffer.capacity() );
        decorator.computeLength();
        decorator.encode( encoded );
        assertTrue( Arrays.equals( buffer.array(), encoded.array() ) );
    }


    @Test(expected = IllegalArgumentException.class)
    public void testDecodeControlWithWrongResultCode() throws Exception
    {
        ByteBuffer buffer = ByteBuffer.allocate( 0x05 );
        buffer.put( new byte[]
            {
               0x30, 0x03,
                0x0A, 0x01, 0x0A
            } );
        buffer.flip();
        
        SortResponseDecorator decorator = new SortResponseDecorator( codec );
        decorator.decode( buffer.array() );
    }

}
