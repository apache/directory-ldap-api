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


import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * A child TLV declaring a length close to Integer.MAX_VALUE used to overflow
 * the int TLV-size arithmetic and bypass the parent length-containment check.
 * It must be rejected with a DecoderException.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class Asn1DecoderTlvSizeOverflowTest
{
    /**
     * A grammar which does nothing : these tests only exercise the TLV
     * structure checks, not any grammar semantics.
     */
    private static final class NoOpGrammar implements Grammar<Asn1Container>
    {
        private String name = "NO_OP";

        @Override
        public void executeAction( Asn1Container container )
        {
            container.setGrammarEndAllowed( true );
        }


        @Override
        public String getName()
        {
            return name;
        }


        @Override
        public void setName( String name )
        {
            this.name = name;
        }
    }


    /**
     * A child TLV whose size overflows an int inside a 16 bytes parent must
     * not pass the containment check
     */
    @Test
    public void testChildTlvSizeOverflowIsRejected()
    {
        Asn1Container container = new AbstractContainer()
        {
        };
        container.setGrammar( new NoOpGrammar() );

        // A SEQUENCE with 16 bytes of room, containing an OCTET STRING
        // claiming 0x7FFFFFFF value bytes : 1 (tag) + 5 (length) + 0x7FFFFFFF
        // wraps negative in int arithmetic
        ByteBuffer stream = ByteBuffer.wrap( new byte[]
            { 0x30, 0x10, 0x04, ( byte ) 0x84, 0x7F, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF } );

        try
        {
            Asn1Decoder.decode( stream, container );
            fail( "A child TLV bigger than its parent must be rejected" );
        }
        catch ( DecoderException expected )
        {
            // expected
        }
    }


    /**
     * A well-formed nested TLV still decodes
     */
    @Test
    public void testNestedTlvStillDecodes() throws DecoderException
    {
        Asn1Container container = new AbstractContainer()
        {
        };
        container.setGrammar( new NoOpGrammar() );

        ByteBuffer stream = ByteBuffer.wrap( new byte[]
            { 0x30, 0x03, 0x04, 0x01, ( byte ) 0xAA } );

        Asn1Decoder.decode( stream, container );
    }
}
