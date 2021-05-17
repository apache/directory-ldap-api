/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.SortResultCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Tests for SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SortResponseControlTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeControl() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x09 );
        bb.put( new byte[]
            {
               0x30, 0x07,
                 0x0A, 0x01, 0x00,
                 ( byte ) 0x80, 0x02,
                   'c', 'n'
            } );
        bb.flip();

        SortResponseFactory factory = ( SortResponseFactory ) codec.getResponseControlFactories().
            get( SortResponse.OID );
        SortResponse control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        assertEquals( SortResultCode.SUCCESS, control.getSortResult() );
        assertEquals( "cn", control.getAttributeName() );

        // test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, control );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeControlWithoutAtType() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
               0x30, 0x03,
                 0x0A, 0x01, 0x10
            } );
        bb.flip();

        SortResponseFactory factory = ( SortResponseFactory ) codec.getResponseControlFactories().
            get( SortResponse.OID );
        SortResponse control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        assertEquals( SortResultCode.NOSUCHATTRIBUTE, control.getSortResult() );
        assertNull( control.getAttributeName() );

        // test reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, control );

        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeControlWithWrongResultCode() throws Exception
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x05 );
        bb.put( new byte[]
            {
               0x30, 0x03,
                 0x0A, 0x01, 0x0A
            } );
        bb.flip();

        SortResponseFactory factory = ( SortResponseFactory ) codec.getResponseControlFactories().
            get( SortResponse.OID );
        SortResponse control = factory.newControl();

        assertThrows( IllegalArgumentException.class, ( ) ->
        {
            factory.decodeValue( control, bb.array() );
        } );
    }
}
