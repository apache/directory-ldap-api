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
package org.apache.directory.api.ldap.codec.bind;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class BindResponseTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a BindResponse
     */
    @Test
    public void testDecodeBindResponseSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x30, 0x0C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x61, 0x07,               // CHOICE { ..., bindResponse BindResponse, ...
                                            // BindResponse ::= APPLICATION[1] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode the BindResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindResponse
        BindResponse bindResponse = container.getMessage();

        assertEquals( 1, bindResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, bindResponse.getLdapResult().getResultCode() );
        assertEquals( "", bindResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", bindResponse.getLdapResult().getDiagnosticMessage() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindResponse with a control
     */
    @Test
    public void testDecodeBindResponseWithControlSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3C );

        stream.put( new byte[]
            {
                0x30, 0x3A,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID
                  0x61, 0x07,                       // CHOICE { ..., bindResponse BindResponse, ...
                                                    // BindResponse ::= APPLICATION[1] SEQUENCE {
                                                    // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,               // LDAPResult ::= SEQUENCE {
                                                    // resultCode ENUMERATED {
                                                    // success (0), ...
                                                    // },
                    0x04, 0x00,                     // matchedDN LDAPDN,
                    0x04, 0x00,                     // errorMessage LDAPString,
                                                    // referral [3] Referral OPTIONAL }
                                                    // serverSaslCreds [7] OCTET STRING OPTIONAL }
                  ( byte ) 0xa0, 0x2C,              // controls
                    0x30, 0x2A,                     // The PagedSearchControl
                      0x04, 0x16,                   // Oid : 1.2.840.113556.1.4.319
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6', '.',
                        '1', '.', '4', '.', '3', '1', '9',
                      0x01, 0x01, ( byte ) 0xff,    // criticality: false
                      0x04, 0x0D,
                        0x30, 0x0B,
                          0x02, 0x01, 0x05,         // Size = 5, cookie = "abcdef"
                          0x04, 0x06,
                            'a', 'b', 'c', 'd', 'e', 'f'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode the BindResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindResponse
        BindResponse bindResponse = container.getMessage();

        assertEquals( 1, bindResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, bindResponse.getLdapResult().getResultCode() );
        assertEquals( "", bindResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", bindResponse.getLdapResult().getDiagnosticMessage() );

        // Check the Control
        Map<String, Control> controls = bindResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "1.2.840.113556.1.4.319" );
        assertEquals( "1.2.840.113556.1.4.319", control.getOid() );
        assertTrue( control instanceof PagedResults );

        PagedResults pagedSearchControl = ( PagedResults ) control;

        assertEquals( 5, pagedSearchControl.getSize() );
        assertArrayEquals( Strings.getBytesUtf8( "abcdef" ), pagedSearchControl.getCookie() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindResponse with an empty credentials
     */
    @Test
    public void testDecodeBindResponseServerSASLEmptyCredentials() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x10 );

        stream.put( new byte[]
            {
                0x30, 0x0E,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x61, 0x09,               // CHOICE { ..., bindResponse BindResponse, ...
                                            // BindResponse ::= APPLICATION[1] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                    ( byte ) 0x87, 0x00     // serverSaslCreds [7] OCTET STRING OPTIONAL
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode the BindResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindResponse
        BindResponse bindResponse = container.getMessage();

        assertEquals( 1, bindResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, bindResponse.getLdapResult().getResultCode() );
        assertEquals( "", bindResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", bindResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "", Strings.utf8ToString( bindResponse.getServerSaslCreds() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
}


    /**
     * Test the decoding of a BindResponse with an empty credentials with
     * controls
     */
    @Test
    public void testDecodeBindResponseServerSASLEmptyCredentialsWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x34 );

        stream.put( new byte[]
            {
                0x30, 0x32,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x61, 0x09,                   // CHOICE { ..., bindResponse BindResponse, ...
                                                // BindResponse ::= APPLICATION[1] SEQUENCE {
                                                // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,           // LDAPResult ::= SEQUENCE {
                                                // resultCode ENUMERATED {
                                                // success (0), ...
                                                // },
                    0x04, 0x00,                 // matchedDN LDAPDN,
                    0x04, 0x00,                 // errorMessage LDAPString,
                                                // referral [3] Referral OPTIONAL }
                    ( byte ) 0x87, 0x00,        // serverSaslCreds [7] OCTET STRING OPTIONAL }
                  ( byte ) 0xA0, 0x22,          // A control
                    0x30, 0x20,
                      0x04, 0x17,               // EntryChange response control
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', 
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '7',
                      0x04, 0x05,               // Control value
                        0x30, 0x03,             // EntryChangeNotification ::= SEQUENCE {
                          0x0A, 0x01, 0x01      //     changeType ENUMERATED {
                                                //         add             (1),
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode the BindResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindResponse
        BindResponse bindResponse = container.getMessage();

        assertEquals( 1, bindResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, bindResponse.getLdapResult().getResultCode() );
        assertEquals( "", bindResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", bindResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "", Strings.utf8ToString( bindResponse.getServerSaslCreds() ) );

        // Check the Control
        Map<String, Control> controls = bindResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );
        assertTrue( control instanceof EntryChange );

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindResponse with a credentials
     */
    @Test
    public void testDecodeBindResponseServerSASL() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x12 );

        stream.put( new byte[]
            {
                0x30, 0x10,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x61, 0x0B,           // CHOICE { ..., bindResponse BindResponse, ...
                                        // BindResponse ::= APPLICATION[1] SEQUENCE {
                                        // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,   // LDAPResult ::= SEQUENCE {
                                        // resultCode ENUMERATED {
                                        // success (0), ...
                                        // },
                    0x04, 0x00,         // matchedDN LDAPDN,
                    0x04, 0x00,         // errorMessage LDAPString,
                                        // referral [3] Referral OPTIONAL }
                    ( byte ) 0x87, 0x02,
                      'A', 'B'          // serverSaslCreds [7] OCTET
                                        // STRING OPTIONAL }
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode the BindResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded BindResponse
        BindResponse bindResponse = container.getMessage();

        assertEquals( 1, bindResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, bindResponse.getLdapResult().getResultCode() );
        assertEquals( "", bindResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", bindResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "AB", Strings.utf8ToString( bindResponse.getServerSaslCreds() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, bindResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindResponse with no LdapResult
     */
    @Test
    public void testDecodeAddResponseEmptyResult() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x61, 0x00,           // CHOICE { ..., bindResponse BindResponse, ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindResponse> container = new LdapMessageContainer<>( codec );

        // Decode a BindResponse message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }
}
