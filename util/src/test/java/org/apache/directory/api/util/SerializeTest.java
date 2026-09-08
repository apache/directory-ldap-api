/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.util;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests for the Serialize buffer helpers. deserializeInt must be the exact
 * inverse of serialize: before byte masking was added, any encoded value whose
 * lower three bytes had the high bit set (e.g. a length of 200) was
 * reconstructed from sign-extended bytes and decoded wrong, silently
 * corrupting round-tripped Rdn/Ava/Value data.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SerializeTest
{
    /**
     * Round-trip values whose byte 1-3 have the high bit set: sign extension
     * decoded 200 (0x000000C8) as -56 before masking was added.
     */
    @Test
    public void testIntRoundTripHighBitBytes()
    {
        int[] values = new int[]
            { 0, 1, 127, 128, 200, 255, 256, 0x80FF, 0xC8C8C8, 0x7FFFFFFF, Integer.MAX_VALUE, -1, Integer.MIN_VALUE };

        for ( int value : values )
        {
            byte[] buffer = new byte[4];
            Serialize.serialize( value, buffer, 0 );

            assertEquals( value, Serialize.deserializeInt( buffer, 0 ) );
        }
    }


    /**
     * Round-trip a byte[] whose length is >= 128: before masking, the length
     * decoded negative and deserializeBytes silently returned an empty array.
     */
    @Test
    public void testBytesRoundTripLengthOver127()
    {
        byte[] value = new byte[200];

        for ( int i = 0; i < value.length; i++ )
        {
            value[i] = ( byte ) i;
        }

        byte[] buffer = new byte[4 + value.length];
        Serialize.serialize( value, buffer, 0 );

        assertArrayEquals( value, Serialize.deserializeBytes( buffer, 0 ) );
    }


    /**
     * A corrupted (negative) encoded length must fail loudly, not silently
     * return an empty array while the caller's cursor desynchronizes.
     */
    @Test
    public void testNegativeLengthIsRejected()
    {
        byte[] buffer = new byte[]
            { ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xC8, 0x00 };

        assertThrows( ArrayIndexOutOfBoundsException.class, () -> Serialize.deserializeBytes( buffer, 0 ) );
    }
}