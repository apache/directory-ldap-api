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
package org.apache.directory.api.ldap.codec.intermediate;


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
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the IntermediateResponse codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class IntermediateResponseTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a full IntermediateResponse
     */
    @Test
    public void testDecodeIntermediateResponseSuccess() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x1D );

        stream.put( new byte[]
            { 
                0x30, 0x1B,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x16,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2', 
                                            // responseValue [1] OCTET STRING OPTIONAL }
                    ( byte ) 0x81, 0x05,
                      'v', 'a', 'l', 'u', 'e' 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );
        assertEquals( "value", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full IntermediateResponse with controls
     */
    @Test
    public void testDecodeIntermediateResponseWithControls() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x44 );

        stream.put( new byte[]
            { 
                0x30, 0x42,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x16,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2', 
                                            // requestValue [1] OCTET STRING OPTIONAL }
                    ( byte ) 0x81, 0x05,
                      'v', 'a', 'l', 'u', 'e', 
                  ( byte ) 0xA0, 0x25,      // A control
                    0x30, 0x23,
                      0x04, 0x16,
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6', 
                        '.', '1', '.', '4', '.', '3', '1', '9',
                      0x04, 0x09,
                        0x30, 0x07,
                         0x02, 0x01, 0x01,
                         0x04, 0x02,
                          'a', 'b'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );
        assertEquals( "value", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check the Control
        Map<String, Control> controls = intermediateResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "1.2.840.113556.1.4.319" );
        assertEquals( "1.2.840.113556.1.4.319", control.getOid() );
        assertTrue( control instanceof PagedResults );
        PagedResults pagedResults = ( PagedResults ) control;
        assertEquals( 1, pagedResults.getSize() );
        assertEquals( "ab", Strings.utf8ToString( pagedResults.getCookie() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full IntermediateResponse with no value and with
     * controls
     */
    @Test
    public void testDecodeIntermediateResponseNoValueWithControls() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3D );

        stream.put( new byte[]
            { 
                0x30, 0x3B,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x0F,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2', 
                                            // requestValue [1] OCTET STRING OPTIONAL }
                  ( byte ) 0xA0, 0x25,      // A control
                    0x30, 0x23,
                      0x04, 0x16,
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6', 
                        '.', '1', '.', '4', '.', '3', '1', '9',
                      0x04, 0x09,
                        0x30, 0x07,
                         0x02, 0x01, 0x01,
                         0x04, 0x02,
                          'a', 'b'

            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check the Control
        Map<String, Control> controls = intermediateResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "1.2.840.113556.1.4.319" );
        assertEquals( "1.2.840.113556.1.4.319", control.getOid() );
        assertTrue( control instanceof PagedResults );
        PagedResults pagedResults = ( PagedResults ) control;
        assertEquals( 1, pagedResults.getSize() );
        assertEquals( "ab", Strings.utf8ToString( pagedResults.getCookie() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an empty IntermediateResponse
     */
    @Test
    public void testDecodeIntermediateResponseEmpty() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            { 
                0x30, 0x05,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x00,           // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a IntermediateResponse PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of an empty OID
     */
    @Test
    public void testDecodeEmptyOID() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            { 
                0x30, 0x07,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x02,           // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                    ( byte ) 0x80, 0x00 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a IntermediateResponse PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a bad name
     */
    @Test
    public void testDecodeExtendedBadRequestName() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x16 );

        stream.put( new byte[]
            { 
                0x30, 0x14,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x0F,           // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                        // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      '1', '-', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2', 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a IntermediateResponse PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a name only IntermediateResponse
     */
    @Test
    public void testDecodeIntermediateResponseName() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x16 );

        stream.put( new byte[]
            { 0x30, 0x14, // LDAPMessage ::= SEQUENCE {
                0x02, 0x01, 0x01, // messageID MessageID
                // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                0x79,
                0x0F, // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                // responseName [0] LDAPOID,
                ( byte ) 0x80,
                0x0D,
                '1',
                '.',
                '3',
                '.',
                '6',
                '.',
                '1',
                '.',
                '5',
                '.',
                '5',
                '.',
                '2', } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an empty value IntermediateResponse
     */
    @Test
    public void testDecodeIntermediateResponseEmptyValue() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x18 );

        stream.put( new byte[]
            { 
                0x30, 0x16,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x11,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      //'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                      //'4', '2', '0', '3', '.', '1', '.', '9', '.', '1', '.', '4',
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                    ( byte ) 0x81, 0x00 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );
        //assertEquals( "1.3.6.1.4.1.4203.1.9.1.4", intermediateResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( 
            new byte[]
                { 
                    0x30, 0x14,                 // LDAPMessage ::= SEQUENCE {
                      0x02, 0x01, 0x01,         // messageID MessageID
                                                // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                      0x79, 0x0F,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                                // responseName [0] LDAPOID,
                        ( byte ) 0x80, 0x0D,
                          '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2'
                }, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an IntermediateResponse without name
     */
    @Test
    public void testDecodeIntermediateResponseNoName() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            { 
                0x30, 0x0C,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x07,           // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                        // responseValue [1] OCTET STRING OPTIONAL,
                    ( byte ) 0x81, 0x05,
                      'v', 'a', 'l', 'u', 'e' 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "", intermediateResponse.getResponseName() );
        assertEquals( "value", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an IntermediateResponse with no value
     */
    @Test
    public void testDecodeIntermediateResponseNoValue() throws EncoderException, DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x16 );

        stream.put( new byte[]
            { 
                0x30, 0x14,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., intermediateResponse IntermediateResponse, ...
                  0x79, 0x0F,               // IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x80, 0x0D,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2', 
                
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<IntermediateResponse> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode the IntermediateResponse PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded IntermediateResponse PDU
        IntermediateResponse intermediateResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, intermediateResponse.getMessageId() );
        assertEquals( "1.3.6.1.5.5.2", intermediateResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( intermediateResponse.getResponseValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, intermediateResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
