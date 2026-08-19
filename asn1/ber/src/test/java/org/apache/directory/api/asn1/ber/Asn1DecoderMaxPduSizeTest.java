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
package org.apache.directory.api.asn1.ber;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the decoder does not commit unbounded memory for an
 * attacker-declared TLV length: the default max PDU size must be finite,
 * and a PDU declaring more than that must be rejected before any
 * allocation is made.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class Asn1DecoderMaxPduSizeTest
{
    /**
     * A minimal concrete container : the decoder throws before any grammar
     * action is needed for the tested PDUs.
     */
    private static final class TestContainer extends AbstractContainer
    {
        TestContainer()
        {
            super();
        }
    }


    /**
     * The default must be bounded, not Integer.MAX_VALUE
     */
    @Test
    public void testDefaultMaxPduSizeIsBounded()
    {
        assertEquals( AbstractContainer.DEFAULT_MAX_PDU_SIZE, new TestContainer().getMaxPDUSize() );
    }


    /**
     * A 6 byte PDU declaring a ~2GB value must be rejected as soon as its
     * length has been decoded, long before 2GB of body bytes ever arrive.
     */
    @Test
    public void testHugeDeclaredLengthIsRejectedByDefault()
    {
        // 30 84 7F FF FF EA : a SEQUENCE declaring a ~2GB value
        ByteBuffer stream = ByteBuffer.allocate( 6 );
        stream.put( new byte[]
            { 0x30, ( byte ) 0x84, 0x7F, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xEA } );
        stream.flip();

        TestContainer container = new TestContainer();

        assertThrows( DecoderException.class, () -> Asn1Decoder.decode( stream, container ) );
    }


    /**
     * The explicit opt-out (a value <= 0) must still remove the limit.
     */
    @Test
    public void testExplicitOptOutRemovesTheLimit() throws DecoderException
    {
        TestContainer container = new TestContainer();
        container.setMaxPDUSize( -1 );

        assertEquals( Integer.MAX_VALUE, container.getMaxPDUSize() );
    }
}
