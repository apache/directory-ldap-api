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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapDecoder;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.model.exception.ResponseCarryingMessageException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.util.Strings;
import org.apache.mina.core.session.DummySession;
import org.apache.mina.core.session.IoSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * A global Ldap Decoder test
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdapDecoderTest extends AbstractCodecServiceTest
{
    /**
     * Decode an incoming buffer into LDAP messages. The result can be 0, 1 or many
     * LDAP messages, which will be stored into the array the caller has created.
     *
     * @param buffer The incoming byte buffer
     * @param messageContainer The LdapMessageContainer which will be used to store the
     * message being decoded. If the message is not fully decoded, the ucrrent state
     * is stored into this container
     * @param decodedMessages The list of decoded messages
     * @throws Exception If the decoding failed
     */
    private void decode( ByteBuffer buffer, LdapMessageContainer<Message> messageContainer,
        List<Message> decodedMessages ) throws DecoderException
    {
        buffer.mark();

        while ( buffer.hasRemaining() )
        {
            try
            {
                Asn1Decoder.decode( buffer, messageContainer );

                if ( messageContainer.getState() == TLVStateEnum.PDU_DECODED )
                {
                    Message message = messageContainer.getMessage();

                    decodedMessages.add( message );

                    messageContainer.clean();
                }
            }
            catch ( DecoderException de )
            {
                buffer.clear();
                messageContainer.clean();

                if ( de instanceof ResponseCarryingException )
                {
                    // Transform the DecoderException message to a MessageException
                    ResponseCarryingMessageException rcme = new ResponseCarryingMessageException( de.getMessage() );
                    rcme.setResponse( ( ( ResponseCarryingException ) de ).getResponse() );

                    throw rcme;
                }
                else
                {
                    // TODO : This is certainly not the way we should handle such an exception !
                    throw new ResponseCarryingException( de.getMessage() );
                }
            }
        }
    }


    /**
     * Test the decoding of a full PDU
     */
    @Test
    public void testDecodeFull() throws DecoderException, EncoderException
    {
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Decode a BindRequest PDU
        Asn1Decoder.decode( stream, container );

        assertEquals( TLVStateEnum.PDU_DECODED, container.getState() );

        // Check the decoded PDU
        BindRequest bindRequest = ( BindRequest ) container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName().toString() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );
        
        // Check the revert encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        LdapEncoder.encodeMessage( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of two messages in a PDU
     */
    @Test
    public void testDecode2Messages() throws DecoderException, EncoderException
    {
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        IoSession dummySession = new DummySession();
        dummySession.setAttribute( LdapDecoder.MESSAGE_CONTAINER_ATTR, container );

        ByteBuffer stream = ByteBuffer.allocate( 0x6A );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x02,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        List<Message> result = new ArrayList<Message>();

        // Decode a BindRequest PDU
        decode( stream, container, result );

        // Check the decoded PDU
        BindRequest bindRequest = ( BindRequest ) ( result.get( 0 ) );

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName().toString() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // The second message
        bindRequest = ( BindRequest ) ( result.get( 1 ) );

        assertEquals( 2, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName().toString() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );
    }


    /**
     * Test the decoding of a partial PDU
     */
    @Test
    public void testDecodePartial() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 16 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '='
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU
        Asn1Decoder.decode( stream, container );

        assertEquals( TLVStateEnum.VALUE_STATE_PENDING, container.getState() );

        // Check the decoded PDU
        Message message = container.getMessage();

        assertEquals( 1, message.getMessageId() );
        assertTrue( message instanceof BindRequest );
        assertTrue( ( ( BindRequest ) message ).isVersion3() );
        assertNull( ( ( BindRequest ) message ).getName() );
        assertTrue( ( ( BindRequest ) message ).isSimple() );
    }


    /**
     * Test the decoding of a splitted PDU
     */
    @Test
    public void testDecodeSplittedPDU() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 16 );
        stream.put( new byte[]
            { 
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=' 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU first block of data
        Asn1Decoder.decode( stream, container );

        assertEquals( TLVStateEnum.VALUE_STATE_PENDING, container.getState() );

        // Second block of data
        stream = ByteBuffer.allocate( 37 );
        stream.put( new byte[]
            { 
                'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 
                'u', ',', 'd', 'c', '=', 'e', 'x', 'a', 
                'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 
                'c', 'o', 'm',
                ( byte ) 0x80, 0x08, // authentication
                // AuthenticationChoice
                // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                // ...
                  'p', 'a', 's', 's', 'w', 'o', 'r', 'd' 
            } );

        stream.flip();

        // Decode a BindRequest PDU second block of data
        Asn1Decoder.decode( stream, container );

        assertEquals( container.getState(), TLVStateEnum.PDU_DECODED );

        // Check the decoded PDU
        BindRequest bindRequest = ( BindRequest ) container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName().toString() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );
        
        // Check the revert encoder
        Asn1Buffer buffer = new Asn1Buffer();
        
        LdapEncoder.encodeMessage( buffer, codec, bindRequest );

        assertArrayEquals( 
            new byte[]
                { 
                    0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                      0x02, 0x01, 0x01,         // messageID MessageID
                      0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                                // BindRequest ::= APPLICATION[0] SEQUENCE {
                        0x02, 0x01, 0x03,       // version INTEGER (1..127),
                        0x04, 0x1F,             // name LDAPDN,
                          'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 
                          'a', 's', 'u', 'l', 'u', ',', 'd', 'c', 
                          '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 
                          ',', 'd', 'c', '=', 'c', 'o', 'm',
                        ( byte ) 0x80, 0x08,    // authentication
                                                // AuthenticationChoice
                                                // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                                // ...
                          'p', 'a', 's', 's', 'w', 'o', 'r', 'd' 

                }, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PDU with a bad Length. The first TLV has a length
     * of 0x32 when the PDU is 0x33 bytes long.
     */
    @Test
    public void testDecodeBadLengthTooSmall() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                // Length should be 0x33...
                0x30, 0x32,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 
                      'a', 's', 'u', 'l', 'u', ',', 'd', 'c', 
                      '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 
                      ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a PDU with a bad primitive Length. The second TLV
     * has a length of 0x02 when the PDU is 0x01 bytes long.
     */
    @Test
    public void testDecodeBadPrimitiveLengthTooBig() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                                            // Length should be 0x01...
                  0x02, 0x02, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a PDU with a bad tag.
     */
    @Test
    public void testDecodeBadTagTransition() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x2D, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication
                                            // AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a split Length.
     *
     * The length is 3 bytes long, but the PDU has been split
     * just after the first byte
     */
    @Test
    public void testDecodeSplittedLength() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 3 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x82, 0x01,  // LDAPMessage ::=SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest PDU first block of data
        Asn1Decoder.decode( stream, container );

        assertEquals( TLVStateEnum.LENGTH_STATE_PENDING, container.getState() );

        // Second block of data
        stream = ByteBuffer.allocate( 1 );
        stream.put( new byte[]
            {
                ( byte ) 0x80 // End of the length
            } );

        stream.flip();

        // Decode a BindRequest PDU second block of data
        Asn1Decoder.decode( stream, container );

        assertEquals( TLVStateEnum.TAG_STATE_START, container.getState() );

        // Check the decoded length
        assertEquals( 384, container.getCurrentTLV().getLength() );
    }


    /**
     * Test that a big PDU is not accepted when the MaxPDU size is set
     */
    @Test
    public void testDecodeOOM() throws DecoderException
    {
        byte[] input = java.util.Base64.getDecoder().decode( "QIR+fnR+yvD/" );
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<Message> container = new LdapMessageContainer<>( codec );
        container.setMaxPDUSize( 1024 );

        // Decode a PDU which is going to be bigger than the MAX PDU size: should throw an exception
        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode( stream, container ); } );
    }
    
    
    @Test
    public void testNullRdnModifyDnRequest() throws DecoderException, EncoderException
    {
        byte[] input = new byte[] 
            {
                0x30, 0x7A,                                     // 122 bytes long message
                  0x02, 0x03, 0x00, 0x31, 0x4A,                 // MessageID : 12 618
                  0x6C, 0x4A,                                   // ModifyDNRequest
                    0x4A, 0x2C,                                 // Entry
                      0x4A, 0x4A, 0x12, 0x12, 0x6E, 0x64, 0x72, 0x6F, // Rubish
                      0x69, 0x64, 0x12, 0x4A, 0x4A, 0x3D, 0x02, 0x2C,
                      0x00, 0x4A, 0x4A, 0x12, 0x12, 0x6E, 0x64, 0x72,
                      0x6F, 0x69, 0x64, 0x12, 0x4A, 0x4A, 0x3D, 0x02,
                      0x2C, 0x00, 0x4A, 0x21, 0x4A, 0x2C
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        try {
            Asn1Decoder.decode(stream, container);
        } catch (DecoderException de) {
            // we expect DecoderException
            return;
        }

        Asn1Buffer buffer = new Asn1Buffer();

        Message message = container.getMessage();
        
        if (message == null) {
            return;
        }

        assertThrows( EncoderException.class, () -> { LdapEncoder.encodeMessage(buffer, codec, message ); } );
    }
    
    
    @Test
    public void testClassCastException() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, (byte)0x82, 0x30, (byte)0x75,             // 12 405 bytes long message
                  0x02, 0x02, 0x26, 0x33,                       // Message ID: 9779
                  0x63, 0x3D,                                   // SearchRequest, 61 bytes long
                    0x04, 0x00,                                 // Base Object RootDSE
                    0x0A, 0x01, 0x02,                           // Scope Base
                    0x0A, 0x01, 0x02,                           // Deref alias
                    0x02, 0x05, 0x00, 0x38, (byte)0xF1, 0x00, 0x44,   // SizeLimite
                    0x02, 0x02, 0x26, 0x3F,                     // TimeLimit
                    0x01, 0x01, 0x00,                           // TypesOnly
                    (byte)0xA9, 0x04,                           // From this point, garbage in...
                      (byte)0x82, 0x02, (byte)0xA1, 0x2E, (byte)0x83, 0x02, (byte)0x87, 0x00, 
                    (byte)0x84, 0x01, 0x00, (byte)0xA9, 0x04, (byte)0x82, 0x02, (byte)0xA1, 0x0E, 
                    (byte)0x83, 0x02, (byte)0xA1, 0x2E, (byte)0x83, 0x26, (byte)0x87, 0x00, 
                    (byte)0x84, 0x01, 0x24, (byte)0xA9, 0x04, (byte)0x82, 0x02, 0x00, (byte)0xFF 
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
    
    
    @Test
    public void testIllegalArgumentException() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, 0x56,                                 // 86 bytes message
                  0x02, 0x02, 0x61, 0x6E,                   // MessageID : 24 942
                  0x64, 0x38,                               // SearchResultEntry
                    0x04, 0x00,                             // ObjectName: rootDSE
                    0x30, 0x0C,                             // Attributes, 12 bytes
                      0x30, 0x04,                           // Partial attribute list, 4 bytes
                        0x04, 0x02, 0x04, 0x20              // Attribute type, rubish
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
    
    
    @Test
    public void testArrayIndexOutOfBoundsException() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, 0x7E,                                                         // Message 126 bytes long
                  0x02, 0x02, 0x4B, 0x4B,                                           // message ID: 19 275
                  0x68, 0x3C,                                                       // AddRequest
                    0x04, 0x02,                                                     // Entry DN
                      0x64, 0x3D,                                                   // "d="
                    0x30, 0x02,                                                     // Attributes
                      0x30, 0x00,                                                   // none
                    0x04, 0x1A,                                                     // Rubish...
                      0x6E, 0x73, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 
                      0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x6E, (byte)0xFB, 
                      (byte)0xFB, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 
                      0x47, 0x47 
            };
        
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
    
    
    @Test
    public void testNumberFormatException() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, 0x50,                                                 // Message 80 bytes long
                  0x02, 0x02, 0x6E, 0x30,                                   // MessageID: 28 208
                  0x50, 0x02, 0x02, 0x6E,                                   // AbandonRequest, ID 622
                  (byte)0xA0, 0x11,                                         // Controls, 17 bytes
                    0x30, 0x0A,                                             // controls, 10 bytes 
                      0x04, 0x07,                                           // Control type
                        0x32, 0x2E, 0x33, 0x30, 0x30, 0x32, 0x2E,           // 2.3002.
                      0x33                                                  // rubish
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
    
    
    @Test
    public void testNullPointerException() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, (byte)0x82, 0x30, 0x47,                       // 12 359 bytes long message
                  0x02, 0x02, 0x26, 0x2E,                           // message ID: 9774
                  0x63, 0x3D,                                       // SearchRequest, 61 bytes long
                    0x04, 0x00,                                     // Base Object RootDSE
                    0x0A, 0x01, 0x02,                               // Scope Base
                    0x0A, 0x01, 0x02,                               // Deref alias
                    0x02, 0x05, 0x00, 0x21, 0x6E, 0x00, 0x51,       // SizeLimit
                    0x02, 0x02, 0x00, 0x03,                         // TimeLimit
                    0x01, 0x01, 0x41,                               // TypesOnly
                    (byte)0xA6, 0x04,                               // Less or equal filter
                      0x04, 0x02,                                   // AttributeDesc
                        0x04, 0x04, 
                    0x04, 0x1F,                                     // AssertionValue, but out of the filter size...
                        0x00, 0x00, 0x00, 0x04, 0x04, 0x02, 0x04, 0x04, 
                        0x30, 0x04, 0x04, 0x02, 0x04, 0x04, 0x30, 0x04, 
                        0x04, 0x02, 0x2E, 0x26, 0x04, 0x03, 0x04, 0x04, 
                        0x04, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                    0x12, 0x12, 0x12, 0x12, 0x12, 0x04, 0x00,       // From this point, garbage
                    0x04, 0x00, 0x04, 0x00, 0x00, 0x40, (byte)0x80, 0x06 
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
    
    
    @Test
    public void testNullPointerException2() throws DecoderException
    {
        byte[] input = new byte[] 
            {
                0x30, (byte)0x82, 0x30, 0x47,                       // 12 359 bytes long message
                  0x02, 0x02, 0x26, 0x2E,                           // message ID: 9774
                  0x63, 0x22,                                       // SearchRequest, 61 bytes long
                    0x04, 0x00,                                     // Base Object RootDSE
                    0x0A, 0x01, 0x02,                               // Scope Base
                    0x0A, 0x01, 0x02,                               // Deref alias
                    0x02, 0x05, 0x00, 0x21, 0x6E, 0x00, 0x51,       // SizeLimite
                    0x02, 0x02, 0x00, 0x03,                         // TimeLimit
                    0x01, 0x01, 0x41,                               // TypesOnly
                    (byte)0xA6, 0x08,                               // Less or equal filter
                      0x04, 0x02,                                   // AttributeDesc
                        0x04, 0x04, 
                      0x04, 0x02,                                   // AssertionValue
                        0x04, 0x04, 
                    0x04, 0x00
            };
        
        ByteBuffer stream = ByteBuffer.allocate(input.length);
        stream.put(input);
        stream.flip();

        LdapApiService codec = new DefaultLdapCodecService();
        LdapMessageContainer<Message> container = new LdapMessageContainer<>(codec);

        assertThrows( DecoderException.class, () -> { Asn1Decoder.decode(stream, container); } );
    }
}
