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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * A global Ldap Decoder test
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdapMessageTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of null length messageId
     */
    @Test
    public void testDecodeMessageLengthNull()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x02 );
        stream.put( new byte[]
            {
                0x30, 0x00, // LDAPMessage ::=SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of null length messageId
     */
    @Test
    public void testDecodeMessageIdLengthNull()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x04 );
        stream.put( new byte[]
            {
                0x30, 0x02,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x00                        // messageID MessageID
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of null length messageId
     */
    @Test
    public void testDecodeMessageIdMinusOne()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x05 );
        stream.put( new byte[]
            {
                0x30, 0x03,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, ( byte ) 0xff         // messageID MessageID = -1
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of messageId which value is -1
     */
    @Test
    public void testDecodeMessageIdMaxInt()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x08 );
        stream.put( new byte[]
            {
                0x30, 0x06,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x04,                       // messageID MessageID = -1
                    ( byte ) 0x7f,( byte ) 0xff, ( byte ) 0xff, ( byte ) 0xff
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of message with nothing but the messqage ID which value is -1
     */
    @Test
    public void testDecodeMessageIdOnly()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x05 );
        stream.put( new byte[]
            {
                0x30, 0x03,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID = 1
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }

    
    /**
     * Test the decoding of a message with a wrong protocol operation
     */
    @Test
    public void testDecodeWrongProtocolOpMaxInt()
    {
        byte[] buffer = new byte[]
            {
                0x30, 0x05,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID = 1
                  0x42, 0x00                        // ProtocolOp
            };
        
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        for ( int i = 0; i < 256; i++ )
        {
            buffer[5] = ( byte ) i;
            stream.put( buffer );
            stream.flip();

            // Allocate a LdapMessage Container
            Asn1Container ldapMessageContainer = new LdapMessageContainer<Message>( codec );

            // Decode a BindRequest PDU
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
            }
            catch ( DecoderException de )
            {
                switch ( i )
                {
                    case 0x42:
                    case 0x4A:
                    case 0x50: // AbandonRequest
                    case 0x60:
                    case 0x61:
                    case 0x63:
                    case 0x64:
                    case 0x65:
                    case 0x66:
                    case 0x67:
                    case 0x68:
                    case 0x69:
                    case 0x6B:
                    case 0x6C:
                    case 0x6D:
                    case 0x6E:
                    case 0x6F:
                    case 0x73:
                    case 0x77:
                    case 0x78:
                        assertTrue( true );
                        break;

                    default:
                        String res = de.getMessage();

                        if ( res.startsWith( "ERR_01200_BAD_TRANSITION_FROM_STATE" )
                            || res.startsWith( "Universal tag " )
                            || res.startsWith( "ERR_01005_TRUNCATED_PDU Truncated PDU" ) )
                        {
                            assertTrue( true );
                        }
                        else
                        {
                            fail( "Bad exception : " + res );
                            return;
                        }

                        break;
                }
            }

            stream.clear();
        }

        assertTrue( true );
    }


    /**
     * Test the decoding of a LdapMessage with a large MessageId
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeUnBindRequestNoControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x08 );
        stream.put( new byte[]
            {
                0x30, 0x06,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x02, 0x01, ( byte ) 0xF4,  // messageID MessageID (500)
                  0x42, 0x00,                       // CHOICE { ..., unbindRequest UnbindRequest,...
                                                    // UnbindRequest ::= [APPLICATION 2] NULL
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<UnbindRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );
 
        Asn1Decoder.decode( stream, ldapMessageContainer );

        Message unbindRequest = ldapMessageContainer.getMessage();

        assertEquals( 500, unbindRequest.getMessageId() );

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, unbindRequest );

        assertArrayEquals( stream.array(), result.array() );
    }
    
    
    /**
     * test a negative length
     */
    @Test
    public void testNegativeLength()
    {
        String base64Bytes = String.join("", "CoT/gwr/Jg==");

        byte[] input = java.util.Base64.getDecoder().decode(base64Bytes);

        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        org.apache.directory.api.ldap.codec.api.LdapApiService codec = new org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode(stream, container);
        } );
    }
}
