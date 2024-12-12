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
package org.apache.directory.api.ldap.codec.modify;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Map;
import java.util.stream.IntStream;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the ModifyRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ModifyRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a ModifyRequest
     */
    @Test
    public void testDecodeModifyRequest2AttrsSuccess()
        throws LdapException, DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x54 );

        stream.put( new byte[]
            {
                0x30, 0x52,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x66, 0x4d,               // CHOICE { ..., modifyRequest ModifyRequest, ...
                                            // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                    'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                    ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                    'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x29,             // modification SEQUENCE OF SEQUENCE {
                      0x30, 0x11,
                        0x0A, 0x01, 0x02,   // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                        0x30, 0x0c,         // AttributeTypeAndValues ::= SEQUENCE {
                          0x04, 0x01,
                            'l',            // type AttributeDescription,
                          0x31, 0x07,       // vals SET OF AttributeValue }
                            0x04, 0x05,
                              'P', 'a', 'r', 'i', 's',
                      0x30, 0x14,           // modification SEQUENCE OF *SEQUENCE* {
                        0x0A, 0x01, 0x00,   // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                        0x30, 0x0f,         // AttributeTypeAndValues ::= SEQUENCE {
                                            // type AttributeDescription,
                          0x04, 0x05,
                            'a', 't', 't', 'r', 's',
                          0x31, 0x06,       // vals SET OF AttributeValue }
                            0x04, 0x04,
                              't', 'e', 's', 't'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Collection<Modification> modifications = modifyRequest.getModifications();

        assertEquals( 2, modifications.size() );

        for ( Modification modification : modifications )
        {
            Attribute attribute = modification.getAttribute();

            if ( "l".equalsIgnoreCase( attribute.getUpId() ) )
            {
                String attrValue = attribute.getString();
                assertEquals( "Paris", attrValue );
            }
            else if ( "attrs".equalsIgnoreCase( attribute.getUpId() ) )
            {
                String attrValue = attribute.getString();
                assertEquals( "test", attrValue );
            }
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest
     */
    @Test
    public void testDecodeModifyRequestBadDN() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x54 );

        stream.put( new byte[]
            {
                0x30, 0x52,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x66, 0x4d,               // CHOICE { ..., modifyRequest ModifyRequest, ...
                                            // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', ':', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x29,
                                            // modification SEQUENCE OF SEQUENCE {
                      0x30, 0x11,
                        0x0A, 0x01, 0x02,   // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                        0x30, 0x0c,         // AttributeTypeAndValues ::= SEQUENCE {
                          0x04, 0x01,
                            'l',            // type AttributeDescription,
                          0x31, 0x07,       // vals SET OF AttributeValue }
                            0x04, 0x05,
                              'P', 'a', 'r', 'i', 's',
                      0x30, 0x14,           // modification SEQUENCE OF *SEQUENCE* {
                        0x0A, 0x01, 0x00,   // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                         0x30, 0x0f,        // AttributeTypeAndValues ::= SEQUENCE {
                                            // type AttributeDescription,
                            0x04, 0x05,
                              'a', 't', 't', 'r', 's',
                            0x31, 0x06,     // vals SET OF AttributeValue }
                              0x04, 0x04,
                                't', 'e', 's', 't'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
            }
            catch ( DecoderException de )
            {
                assertTrue( de instanceof ResponseCarryingException );
                Message response = ( ( ResponseCarryingException ) de ).getResponse();
                assertTrue( response instanceof ModifyResponseImpl );
                assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( ModifyResponseImpl ) response ).getLdapResult()
                    .getResultCode() );
    
                throw de;
            }
        } );
    }


    /**
     * Test the decoding of a ModifyRequest, with different operations
     */
    @Test
    public void testDecodeModifyRequestManyOperations()
        throws LdapException, DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x8C );

        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x89,
                  0x02, 0x01, 0x015,        // messageID MessageID
                  0x66, 0x67,
                    0x04, 0x2B,             // ModifyRequest object : cn=Tori Amos,ou=playground,dc=apache,dc=org
                      'c', 'n', '=', 'T', 'o', 'r', 'i', ' ', 'A', 'm', 'o', 's', ',',
                      'o', 'u', '=', 'p', 'l', 'a', 'y', 'g', 'r', 'o', 'u', 'n', 'd', ',',
                      'd', 'c', '=', 'a', 'p', 'a', 'c', 'h', 'e', ',', 'd', 'c', '=', 'o', 'r', 'g',
                    0x30, 0x38,             // Modifications
                      0x30, 0x24,           // Modification
                        0x0A, 0x01, 0x00,   // Operation = ADD
                        0x30, 0x1F,         // type : telephoneNumber
                          0x04, 0x0F,
                            't', 'e', 'l', 'e', 'p', 'h', 'o', 'n', 'e', 'n', 'u', 'm', 'b', 'e', 'r',
                          0x31, 0x0C,       // vals : 1234567890
                            0x04, 0x0A,
                              '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                      0x30, 0x10,           // Modification
                        0x0A, 0x01, 0x02,   // Operation = REPLACE
                        0x30, 0x0B,         // type : cn
                          0x04, 0x02,
                            'c', 'n',
                          0x31, 0x05,       // vals : XXX
                            0x04, 0x03,
                              'X', 'X', 'X',
                  ( byte ) 0xA0, 0x1B,      // Control : 2.16.840.1.113730.3.4.2
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 21, modifyRequest.getMessageId() );
        assertEquals( "cn=Tori Amos,ou=playground,dc=apache,dc=org", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 2, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "telephonenumber", Strings.toLowerCaseAscii( attributeValue.getId() ) );

        String attrValue = attributeValue.getString();
        assertEquals( "1234567890", attrValue );

        modification = ( Modification ) modifications[1];
        attributeValue = modification.getAttribute();

        assertEquals( "cn", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );

        attrValue = attributeValue.getString();
        assertEquals( "XXX", attrValue );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest, with different operations, take 2
     */
    @Test
    public void testDecodeModifyRequestManyOperations2()
        throws LdapException, DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0xB9 );

        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0xB6,     // LdapMessage
                  0x02, 0x01, 0x31,                     // messageID MessageID
                  0x66, ( byte ) 0x81, ( byte ) 0x93,   // ModifyRequest
                    0x04, 0x2B,                         // ModifyRequest object : cn=Tori Amos,ou=playground,dc=apache,dc=org
                      'c', 'n', '=', 'T', 'o', 'r', 'i', ' ', 'A', 'm', 'o', 's', ',',
                      'o', 'u', '=', 'p', 'l', 'a', 'y', 'g', 'r', 'o', 'u', 'n', 'd', ',',
                      'd', 'c', '=', 'a', 'p', 'a', 'c', 'h', 'e', ',', 'd', 'c', '=', 'o', 'r', 'g',
                    0x30, 0x64,                         // Modifications
                      0x30, 0x14,                       // Modification
                        0x0A, 0x01, 0x01,               // Operation : Delete
                        0x30, 0x0F,                     // type : description
                          0x04, 0x0B,
                            'd', 'e', 's', 'c', 'r', 'i', 'p', 't', 'i', 'o', 'n',
                        0x31, 0x00,                     // Vals = null
                      0x30, 0x25,                       // Modification
                        0x0A, 0x01, 0x00,               // Operation : Add
                        0x30, 0x20,                     // type : telephoneNumber
                          0x04, 0x0F,
                            't', 'e', 'l', 'e', 'p', 'h', 'o', 'n', 'e', 'n', 'u', 'm', 'b', 'e', 'r',
                          0x31, 0x0D,                   // Vals : 01234567890
                            0x04, 0x0B,
                              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                      0x30, 0x25,                       // Modification
                        0x0A, 0x01, 0x00,               // Operation : Add
                        0x30, 0x20,                     // type : telephoneNumber
                          0x04, 0x0F,
                            't', 'e', 'l', 'e', 'p', 'h', 'o', 'n', 'e', 'n', 'u', 'm', 'b', 'e', 'r',
                          0x31, 0x0D,                   // Vals : 01234567890
                            0x04, 0x0B,
                              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
                  ( byte ) 0xA0, 0x1B,                  // Controls : 2.16.840.1.113730.3.4.2
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=Tori Amos,ou=playground,dc=apache,dc=org", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 3, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "description", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 0, attributeValue.size() );

        modification = ( Modification ) modifications[1];
        attributeValue = modification.getAttribute();

        String attrValue = attributeValue.getString();

        assertEquals( "telephonenumber", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );

        assertEquals( "01234567890", attrValue );

        modification = ( Modification ) modifications[2];
        attributeValue = modification.getAttribute();

        attrValue = attributeValue.getString();

        assertEquals( "telephonenumber", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );

        attrValue = attributeValue.getString();
        assertEquals( "01234567890", attrValue );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest
     */
    @Test
    public void testDecodeModifyRequest2Attrs3valsSuccess()
        throws LdapException, DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x5C );

        stream.put( new byte[]
            {
                0x30, 0x5A,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x66, 0x55,               // CHOICE { ..., modifyRequest ModifyRequest, ...
                                            // ModifyRequest ::= [APPLICATION 6] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x31,             // modification SEQUENCE OF SEQUENCE {
                        0x30, 0x19,
                          0x0A, 0x01, 0x02, // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                          0x30, 0x14,       // AttributeTypeAndValues ::= SEQUENCE {
                            0x04, 0x01,
                              'l',          // type AttributeDescription,
                            0x31, 0x0F,     // vals SET OF AttributeValue }
                              0x04, 0x05,
                                'P', 'a', 'r', 'i', 's',
                              0x04, 0x06,
                                'L', 'o', 'n', 'd', 'o', 'n',
                          0x30, 0x14,       // modification SEQUENCE OF *SEQUENCE*  {
                            0x0A, 0x01, 0x00, // operation ENUMERATED {
                                            // add (0),
                                            // delete (1),
                                            // replace (2) },
                                            // modification AttributeTypeAndValues } }
                            0x30, 0x0f,     // AttributeTypeAndValues ::= SEQUENCE {
                                            // type AttributeDescription,
                              0x04, 0x05,
                                'a', 't', 't', 'r', 's',
                              0x31, 0x06,   // vals SET OF AttributeValue }
                                0x04, 0x04,
                                  't', 'e', 's', 't'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 2, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "l", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );

        assertTrue( attributeValue.contains( "Paris" ) );
        assertTrue( attributeValue.contains( "London" ) );

        modification = ( Modification ) modifications[1];
        attributeValue = modification.getAttribute();

        assertEquals( "attrs", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );

        String attrValue = attributeValue.getString();
        assertEquals( "test", attrValue );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a ModifyRequest with an empty body
     */
    @Test
    public void testDecodeModifyRequestEmptyBody() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x00            // ModifyRequest
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an empty object
     */
    @Test
    public void testDecodeModifyRequestEmptyObject() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            {
                0x30, 0x07,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x02,           // ModifyRequest
                    0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an object and nothing else
     */
    @Test
    public void testDecodeModifyRequestObjectAlone() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x29 );

        stream.put( new byte[]
            {
                0x30, 0x27,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x22,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                    'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                    ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                    'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an empty modification
     */
    @Test
    public void testDecodeModifyRequestEmptyModification() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2B );

        stream.put( new byte[]
            {
                0x30, 0x29,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x24,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an empty operation
     */
    @Test
    public void testDecodeModifyRequestEmptyOperation() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2D );

        stream.put( new byte[]
            {
                0x30, 0x2B,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x26,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x02,
                      0x30, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an wrong empty operation
     */
    @Test
    public void testDecodeModifyRequestWrongOperationEmpty() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2F );

        stream.put( new byte[]
            {
                0x30, 0x2D,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x28,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x04,
                      0x30, 0x02,
                        0x0A, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an wrong operation
     */
    @Test
    public void testDecodeModifyRequestWrongOperation() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x30 );

        stream.put( new byte[]
            {
                0x30, 0x2E,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x29,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x05,
                      0x30, 0x03,
                        0x0A, 0x01, 0x04
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and nothing
     * more
     */
    @Test
    public void testDecodeModifyRequestAddOperationEnd() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x30 );

        stream.put( new byte[]
            {
                0x30, 0x2E,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x29,           // ModifyRequest
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x05,
                      0x30, 0x03,
                        0x0A, 0x01, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and an empty
     * modification
     */
    @Test
    public void testDecodeModifyRequestAddOperationEmptyModification() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x32 );

        stream.put( new byte[]
            {
                0x30, 0x30,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x2B,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x07,
                      0x30, 0x05,
                        0x0A, 0x01, 0x00,
                      0x30, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with an empty type
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationEmptyType() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x34 );

        stream.put( new byte[]
            {
                0x30, 0x32,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x2D,           // ModifyRequest
                    0x04, 0x20,             // object OCTET STRING,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x09,             // changes *SEQUENCE OF* change SEQUENCE {
                      0x30, 0x07,           // changes SEQUENCE OF change *SEQUENCE* {
                        0x0A, 0x01, 0x00,   // operation       ENUMERATED { add     (0),
                        0x30, 0x02,         // modification    PartialAttribute } }
                          0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
                fail( "We should never reach this point !!!" );
            }
            catch ( DecoderException de )
            {
                de.printStackTrace();
                assertTrue( de instanceof ResponseCarryingException );
                Message response = ( ( ResponseCarryingException ) de ).getResponse();
                assertTrue( response instanceof ModifyResponseImpl );
                assertEquals( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, ( ( ModifyResponseImpl ) response ).getLdapResult()
                    .getResultCode() );
    
                throw de;
            }
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with a type and no vals
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationTypeNoVals() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );

        stream.put( new byte[]
            {
                0x30, 0x33,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x2E,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x0A,
                      0x30, 0x08,
                        0x0A, 0x01, 0x00,
                        0x30, 0x03,
                          0x04, 0x01,
                            'l'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with a type and an empty vals
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationTypeEmptyVals()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x37 );

        stream.put( new byte[]
            {
                0x30, 0x35,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x30,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x0C,
                      0x30, 0x0A,
                        0x0A, 0x01, 0x00,
                        0x30, 0x05,
                           0x04, 0x01,
                            'l',
                           0x31, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 1, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "l", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 0, attributeValue.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with a type and an empty vals wuth controls
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationTypeEmptyValsWithControls()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x54 );

        stream.put( new byte[]
            {
                0x30, 0x52,                 // LdapMessage
                  0x02, 0x01, 0x31,         // messageID MessageID
                  0x66, 0x30,               // ModifyRequest
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x0C,
                      0x30, 0x0A,
                        0x0A, 0x01, 0x00,
                        0x30, 0x05,
                          0x04, 0x01,
                            'l',
                        0x31, 0x00,
                  ( byte ) 0xA0, 0x1B,      // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1',  '.', '1', '1', '3', '7', '3', '0',
                        '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 1, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "l", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 0, attributeValue.size() );

        // Check the Control
        Map<String, Control> controls = modifyRequest.getControls();

        assertEquals( 1, controls.size() );

        Control control = modifyRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with a type and two vals
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationType2Vals()
        throws LdapException, DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3D );

        stream.put( new byte[]
            {
                0x30, 0x3B,                 // LdapMessage
                  0x02, 0x01, 0x31,         // messageID MessageID
                  0x66, 0x36,               // ModifyRequest
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x12,
                      0x30, 0x10,
                        0x0A, 0x01, 0x00,
                        0x30, 0x0B,
                          0x04, 0x01,
                            'l',
                        0x31, 0x06,
                          0x04, 0x01,
                            'a',
                          0x04, 0x01,
                            'b'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 1, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "l", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 2, attributeValue.size() );

        assertTrue( attributeValue.contains( "a" ) );
        assertTrue( attributeValue.contains( "b" ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest with an increment operation, and a
     * modification with a type and one value
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationIncrement()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x42 );

        stream.put( new byte[]
            {
                0x30, 0x40,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x3B,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x017,
                      0x30, 0x15,
                        0x0A, 0x01, 0x03,
                        0x30, 0x10,
                           0x04, 0x09,
                             'u', 'i', 'd', 'n', 'u', 'm', 'b', 'e', 'r',
                           0x31, 0x03,
                             0x04, 0x01, 0x31
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 1, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        
        assertEquals( ModificationOperation.INCREMENT_ATTRIBUTE, modification.getOperation() );
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "uidnumber", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 1, attributeValue.size() );

        assertEquals( "1", attributeValue.get().getString() );
        
        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyRequest with an increment operation, and a
     * modification with a type and no value
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationIncrementNoValue()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x3D );

        stream.put( new byte[]
            {
                0x30, 0x3B,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x36,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x012,
                      0x30, 0x10,
                        0x0A, 0x01, 0x03,
                        0x30, 0x0B,
                           0x04, 0x09,
                             'u', 'i', 'd', 'n', 'u', 'm', 'b', 'e', 'r',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an increment operation applied on an attribute which 
     * does not have an INTEGER or a NUMERIC STRING syntax.
     * 
     * CANT BE TESTED WITHOUT A SCHEMA...
     *
    @Test
    public void testDecodeModifyRequestAddOperationModificationIncrementNotIntegerAttribute()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x42 );

        stream.put( new byte[]
            {
                0x30, 0x40,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x3B,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x017,
                      0x30, 0x15,
                        0x0A, 0x01, 0x03,
                        0x30, 0x10,
                           0x04, 0x09,
                             'g', 'i', 'v', 'e', 'n', 'N', 'a', 'm', 'e',        // Not a valid attribute
                           0x31, 0x03,
                             0x04, 0x01, 0x01
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }

    
    /**
     * Test the decoding of a ModifyRequest with an increment operation, and a
     * modification with a type and two values
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationIncrementTwoValues()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x45 );

        stream.put( new byte[]
            {
                0x30, 0x43,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x3E,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x01A,
                      0x30, 0x18,
                        0x0A, 0x01, 0x03,
                        0x30, 0x13,
                          0x04, 0x09,
                            'u', 'i', 'd', 'n', 'u', 'm', 'b', 'e', 'r',
                          0x31, 0x06,
                            0x04, 0x01, 0x31,
                            0x04, 0x01, 0x32
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyRequest with an add operation, and a
     * modification with a type and an empty vals
     */
    @Test
    public void testDecodeModifyRequestAddOperationModificationIncrementWithValue()
        throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x42 );

        stream.put( new byte[]
            {
                0x30, 0x40,             // LdapMessage
                  0x02, 0x01, 0x31,     // messageID MessageID
                  0x66, 0x3B,           // ModifyRequest
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x30, 0x017,
                      0x30, 0x15,
                        0x0A, 0x01, 0x03,
                        0x30, 0x10,
                           0x04, 0x09,
                            'u', 'i', 'd', 'n', 'u', 'm', 'b', 'e', 'r',
                           0x31, 0x03,
                             0x04, 0x01,
                               '3'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyRequest PDU
        Asn1Decoder.decode( stream, ldapMessageContainer );

        // Check the decoded PDU
        ModifyRequest modifyRequest = ldapMessageContainer.getMessage();

        assertEquals( 49, modifyRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyRequest.getName().toString() );

        Object[] modifications = modifyRequest.getModifications().toArray();

        assertEquals( 1, modifications.length );

        Modification modification = ( Modification ) modifications[0];
        
        assertEquals( ModificationOperation.INCREMENT_ATTRIBUTE, modification.getOperation() );
        Attribute attributeValue = modification.getAttribute();

        assertEquals( "uidnumber", Strings.toLowerCaseAscii( attributeValue.getUpId() ) );
        assertEquals( 1, attributeValue.size() );
        assertEquals( "3", attributeValue.get().getString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test that encoding and decoding of a modify request with 10k attributes and 10k values
     * succeeds without StackOverflowError (DIRAPI-368, DIRSERVER-2340).
     */
    @Test
    public void testEncodeDecodeLarge() throws DecoderException, EncoderException, LdapException
    {
        Asn1Buffer buffer = new Asn1Buffer();

        ModifyRequest originalModifyRequest = new ModifyRequestImpl();
        originalModifyRequest.setMessageId( 3 );
        Dn dn = new Dn( "cn=test,ou=users,ou=system" );
        originalModifyRequest.setName( dn );
        for ( int modIndex = 0; modIndex < 100000; modIndex++ )
        {
            originalModifyRequest.addModification( new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE,
                "objectclass" + modIndex, "top", "person" ) );
        }
        String[] values = IntStream.range( 0, 100000 ).boxed().map( i -> "value" + i ).toArray( String[]::new );
        originalModifyRequest.addModification(
            new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, "objectclass", values ) );

        LdapEncoder.encodeMessage( buffer, codec, originalModifyRequest );

        LdapMessageContainer<ModifyRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( buffer.getBytes(), ldapMessageContainer );

        ModifyRequest decodedModifyRequest = ldapMessageContainer.getMessage();

        assertEquals( originalModifyRequest, decodedModifyRequest );
    }

}
