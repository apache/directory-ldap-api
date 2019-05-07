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
package org.apache.directory.api.ldap.codec.del;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the DelResponse codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class DelResponseTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a DelResponse
     */
    @Test
    public void testDecodeDelResponseSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2D );

        stream.put( new byte[]
            {
                0x30, 0x2B,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x6B, 0x26,               // CHOICE { ..., delResponse DelResponse, ...
                                            // DelResponse ::= [APPLICATION 11] LDAPResult
                    0x0A, 0x01, 0x21,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // aliasProblem (33), ...
                                            // },
                    0x04, 0x1F,             // matchedDN LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x04, 0x00              // errorMessage
                                            // LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteResponse> container = new LdapMessageContainer<>( codec );

        // Decode the DelResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded DelResponse PDU
        DeleteResponse delResponse = container.getMessage();

        assertEquals( 1, delResponse.getMessageId() );
        assertEquals( ResultCodeEnum.ALIAS_PROBLEM, delResponse.getLdapResult().getResultCode() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", delResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", delResponse.getLdapResult().getDiagnosticMessage() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, delResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a DelResponse with no LdapResult
     */
    @Test
    public void testDecodeDelResponseEmptyResult() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x6B, 0x00,               // CHOICE { ..., delResponse DelResponse, ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteResponse> container = new LdapMessageContainer<>( codec );

        // Decode a DelResponse message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a DelResponse with controls
     */
    @Test
    public void testDecodeDelResponseSuccessWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x51 );

        stream.put( new byte[]
            {
                0x30, 0x4F,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x6B, 0x26,               // CHOICE { ..., delResponse DelResponse, ...
                                            // DelResponse ::= [APPLICATION 11] LDAPResult
                    0x0A, 0x01, 0x21,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (21), ...
                                            // },
                    0x04, 0x1F,             // matchedDN LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x04, 0x00,             // errorMessage
                                            // LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
                  ( byte ) 0xA0, 0x22,      // A control
                    0x30, 0x20,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '7',
                      0x04, 0x05,           // Control value
                        0x30, 0x03,         // EntryChangeNotification ::= SEQUENCE {
                          0x0A, 0x01, 0x01  //     changeType ENUMERATED {
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteResponse> container = new LdapMessageContainer<>( codec );

        // Decode the DelResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded DelResponse PDU
        DeleteResponse delResponse = container.getMessage();

        assertEquals( 1, delResponse.getMessageId() );
        assertEquals( ResultCodeEnum.ALIAS_PROBLEM, delResponse.getLdapResult().getResultCode() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", delResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", delResponse.getLdapResult().getDiagnosticMessage() );

        // Check the Control
        Map<String, Control> controls = delResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );
        assertTrue( control instanceof EntryChange );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, delResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
