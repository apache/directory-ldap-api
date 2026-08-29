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
package org.apache.directory.api.ldap.codec;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that a zero-length controlValue OCTET STRING does not propagate a null
 * value into a control factory. For a factory-backed control (pagedResults) the
 * decoder must fail with a clean DecoderException (protocol error), never with
 * an uncaught NullPointerException; for an unknown (opaque) control the empty
 * value must be stored as an empty byte array.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class ZeroLengthControlValueTest extends AbstractCodecServiceTest
{
    /**
     * Decode an AbandonRequest carrying a pagedResults control (registered by
     * default) whose controlValue is the empty OCTET STRING (04 00).
     */
    @Test
    public void testDecodeZeroLengthPagedResultsControlValue()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x26 );
        stream.put( new byte[]
            {
                0x30, 0x24,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x03,             // messageID MessageID
                  0x50, 0x01, 0x02,             // CHOICE { ..., abandonRequest
                  ( byte ) 0xA0, 0x1C,          // controls [0] Controls OPTIONAL }
                    0x30, 0x1A,                 // Control ::= SEQUENCE {
                      0x04, 0x16,               // controlType LDAPOID (PagedResults)
                        '1', '.', '2', '.', '8', '4', '0', '.',
                        '1', '1', '3', '5', '5', '6', '.', '1',
                        '.', '4', '.', '3', '1', '9',
                      0x04, 0x00                // controlValue OCTET STRING (empty)
            } );

        stream.flip();

        LdapMessageContainer<AbandonRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Must be a clean protocol error, not a NullPointerException
        assertThrows( DecoderException.class,
            () -> Asn1Decoder.decode( stream, ldapMessageContainer ) );
    }


    /**
     * Decode an AbandonRequest carrying an unknown (opaque) control with an
     * empty controlValue: the decode must succeed and the stored encoded
     * value must be an empty byte array, not null.
     *
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodeZeroLengthOpaqueControlValue() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x21 );
        stream.put( new byte[]
            {
                0x30, 0x1F,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x03,             // messageID MessageID
                  0x50, 0x01, 0x02,             // CHOICE { ..., abandonRequest
                  ( byte ) 0xA0, 0x17,          // controls [0] Controls OPTIONAL }
                    0x30, 0x15,                 // Control ::= SEQUENCE {
                      0x04, 0x11,               // controlType LDAPOID (unknown)
                        '1', '.', '3', '.', '6', '.', '1', '.',
                        '4', '.', '1', '.', '4', '2', '.', '4',
                        '2',
                      0x04, 0x00                // controlValue OCTET STRING (empty)
            } );

        stream.flip();

        LdapMessageContainer<AbandonRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        AbandonRequest abandonRequest = ldapMessageContainer.getMessage();
        Control control = abandonRequest.getControls().get( "1.3.6.1.4.1.42.42" );

        assertArrayEquals( Strings.EMPTY_BYTES, ( ( OpaqueControl ) control ).getEncodedValue() );
    }
}
