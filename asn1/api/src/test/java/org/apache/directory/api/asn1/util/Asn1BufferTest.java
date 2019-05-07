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
package org.apache.directory.api.asn1.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Test for the Asn1Buffer class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Asn1BufferTest
{
    @Test
    public void testPutSmallBytes()
    {
        Asn1Buffer buffer = new Asn1Buffer();

        for ( int i = 0; i < 512; i++ )
        {
            buffer.put( new byte[] { 0x01, ( byte ) i } );
        }

        assertEquals( 1024, buffer.getPos() );
        ByteBuffer result = buffer.getBytes();

        for ( int i = 0; i < 512; i++ )
        {
            assertEquals( 0x01, result.get( i + i ) );
            assertEquals( ( byte ) ( 511 - i ), result.get( i + i + 1 ) );
        }
    }


    @Test
    public void testPutByte()
    {
        Asn1Buffer buffer = new Asn1Buffer();

        for ( int i = 0; i < 1024; i++ )
        {
            buffer.put( ( byte ) i );
        }

        assertEquals( 1024, buffer.getPos() );
        ByteBuffer result = buffer.getBytes();

        for ( int i = 0; i < 1024; i++ )
        {
            assertEquals( ( byte ) ( 1023 - i ), result.get( i ) );
        }
    }


    @Test
    public void testPutByteOOB()
    {
        Asn1Buffer buffer = new Asn1Buffer();

        for ( int i = 0; i < 1025; i++ )
        {
            buffer.put( ( byte ) i );
        }

        assertEquals( 1025, buffer.getPos() );
        assertEquals( 2048, buffer.getSize() );
        ByteBuffer result = buffer.getBytes();

        for ( int i = 0; i < 1025; i++ )
        {
            assertEquals( ( byte ) ( 1024 - i ), result.get( i ) );
        }
    }

    @Test
    @Disabled
    public void testBytesPerf()
    {
        long t0 = System.currentTimeMillis();

        for ( int j = 0; j < 1000; j++ )
        {
            Asn1Buffer buffer = new Asn1Buffer();

            for ( int i = 0; i < 409600; i++ )
            {
                buffer.put( new byte[] { 0x01, ( byte ) i } );
            }
        }

        long t1 = System.currentTimeMillis();

        System.out.println( "Delta: " + ( t1 - t0 ) );
    }
}
