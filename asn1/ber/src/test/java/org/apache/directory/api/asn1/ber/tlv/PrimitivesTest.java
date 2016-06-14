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
package org.apache.directory.api.asn1.ber.tlv;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the Primitives
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class PrimitivesTest
{
    /**
     * Test the Integer Primitive
     */
    @Test
    public void testIntegerPrimitive() throws IntegerDecoderException
    {
        BerValue value = new BerValue();

        value.init( 1 );
        value.setData( new byte[]
            { 0x00 } ); // res = 0
        assertEquals( 0, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 1 );
        value.setData( new byte[]
            { 0x01 } ); // res = 1
        assertEquals( 1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 1 );
        value.setData( new byte[]
            { ( byte ) 0xFF } ); // res = 255
        assertEquals( -1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { ( byte ) 0x00, ( byte ) 0xFF } ); // res = 255
        assertEquals( 255, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x00, 0x01 } ); // res = 1
        assertEquals( 1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x01, 0x00 } ); // res = 256
        assertEquals( 256, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x01, 0x01 } ); // res = 257
        assertEquals( 257, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x01, ( byte ) 0xFF } ); // res = 511
        assertEquals( 511, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x02, 0x00 } ); // res = 512
        assertEquals( 512, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { 0x7F, ( byte ) 0xFF } ); // res = 32767
        assertEquals( 32767, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { ( byte ) 0x80, 0x00 } ); // res = -32768
        assertEquals( -32768, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 2 );
        value.setData( new byte[]
            { ( byte ) 0xFF, ( byte ) 0xFF } ); // res = -65535
        assertEquals( -1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 3 );
        value.setData( new byte[]
            { 0x00, ( byte ) 0xFF, ( byte ) 0xFF } ); // res = 65535
        assertEquals( 65535, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 3 );
        // res = 65536
        value.setData( new byte[]
            { 0x01, 0x00, 0x00 } );
        assertEquals( 65536, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 3 );
        // res = 8388607
        value.setData( new byte[]
            { 0x7F, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( 8388607, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 3 );
        // res = -8388608
        value.setData( new byte[]
            { ( byte ) 0x80, ( byte ) 0x00, ( byte ) 0x00 } );
        assertEquals( -8388608, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 3 );
        // res = -1
        value.setData( new byte[]
            { ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( -1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 4 );
        // res = 16777215
        value.setData( new byte[]
            { 0x00, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( 16777215, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 4 );
        // res = 2^31 - 1 = MaxInt
        value.setData( new byte[]
            { ( byte ) 0x7F, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( Integer.MAX_VALUE, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 4 );
        // res = 2^31 = MinInt
        value.setData( new byte[]
            { ( byte ) 0x80, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 } );
        assertEquals( Integer.MIN_VALUE, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 4 );
        // res = -1
        value.setData( new byte[]
            { ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( -1, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 5 );
        // res = 2^31 = MinInt
        value.setData( new byte[]
            { 0x00, ( byte ) 0x80, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 } );
        assertEquals( Integer.MIN_VALUE, IntegerDecoder.parse( value ) );
        value.reset();

        value.init( 5 );
        // res = 2^31 = MinInt
        value.setData( new byte[]
            { 0x00, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );
        assertEquals( -1, IntegerDecoder.parse( value ) );
        value.reset();

        try
        {
            value.init( 5 );
            // res = 2^31 = MinInt
            value.setData( new byte[]
                { 0x00, ( byte ) 0x7F, ( byte ) 0x00, ( byte ) 0x00, ( byte ) 0x00 } ); // res
            IntegerDecoder.parse( value );
            fail();
        }
        catch ( IntegerDecoderException ide )
        {
            // Expected
        }
    }
} // end class TLVTagDecoderTest
