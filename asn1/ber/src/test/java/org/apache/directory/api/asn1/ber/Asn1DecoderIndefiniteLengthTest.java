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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * The BER indefinite length form (length octet 0x80) is not supported by this
 * decoder : it must be rejected with a DecoderException instead of being
 * silently decoded as a zero length, which would create a parser differential
 * with conforming BER decoders.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class Asn1DecoderIndefiniteLengthTest
{
    /**
     * A constructed TLV using the indefinite length form must be rejected
     */
    @Test
    public void testIndefiniteLengthIsRejected()
    {
        Asn1Container container = new AbstractContainer()
        {
        };

        // SEQUENCE with the indefinite length octet, then end-of-contents
        ByteBuffer stream = ByteBuffer.wrap( new byte[]
            { 0x30, ( byte ) 0x80, 0x00, 0x00 } );

        try
        {
            Asn1Decoder.decode( stream, container );
            fail( "The indefinite length form must be rejected" );
        }
        catch ( DecoderException expected )
        {
            // expected
        }
    }


    /**
     * A primitive TLV using the indefinite length form must be rejected too
     */
    @Test
    public void testIndefiniteLengthOnPrimitiveIsRejected()
    {
        Asn1Container container = new AbstractContainer()
        {
        };

        // OCTET STRING with the indefinite length octet
        ByteBuffer stream = ByteBuffer.wrap( new byte[]
            { 0x04, ( byte ) 0x80, 0x00, 0x00 } );

        try
        {
            Asn1Decoder.decode( stream, container );
            fail( "The indefinite length form must be rejected" );
        }
        catch ( DecoderException expected )
        {
            // expected
        }
    }
}
