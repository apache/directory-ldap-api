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
package org.apache.directory.api.ldap.codec.add;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
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
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponseImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaITImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the AddRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class AddRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a AddRequest
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeAddRequestSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x59 );

        stream.put( new byte[]
            {
                0x30, 0x57,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x68, 0x52,               // CHOICE { ..., addRequest AddRequest, ...
                                            // AddRequest ::= [APPLICATION 8] SEQUENCE {
                                            // entry LDAPDN,
                    0x04, 0x20,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                            // attributes AttributeList }
                    0x30, 0x2E,             // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x0c,           // attribute 1
                        0x04, 0x01,         // type AttributeDescription,
                          'l',
                        0x31, 0x07,         // vals SET OF AttributeValue }
                          0x04, 0x05,
                            'P', 'a', 'r', 'i', 's',
                      0x30, 0x1E,           // attribute 2
                        0x04, 0x05,         // type AttributeDescription,
                          'a', 't', 't', 'r', 's',
                        0x31, 0x15,         // vals SET OF AttributeValue }
                          0x04, 0x05,
                            't', 'e', 's', 't', '1',
                          0x04, 0x05,
                            't', 'e', 's', 't', '2',
                          0x04, 0x05,
                            't', 'e', 's', 't', '3'
            } );

        Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        Asn1Decoder.decode( stream, container );

        AddRequest addRequest = container.getMessage();

        // Check the decoded message
        assertEquals( 1, addRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", addRequest.getEntryDn().toString() );

        Entry entry = addRequest.getEntry();

        assertEquals( 2, entry.size() );

        Set<String> expectedTypes = new HashSet<String>();

        expectedTypes.add( "l" );
        expectedTypes.add( "attrs" );

        Map<String, Set<String>> typesVals = new HashMap<String, Set<String>>();

        Set<String> lVal1 = new HashSet<String>();
        lVal1.add( "Paris" );
        typesVals.put( "l", lVal1 );

        Set<String> lVal2 = new HashSet<String>();
        lVal2.add( "test1" );
        lVal2.add( "test2" );
        lVal2.add( "test3" );
        typesVals.put( "attrs", lVal2 );

        Attribute attribute = entry.get( "l" );

        assertTrue( expectedTypes.contains( Strings.toLowerCaseAscii( attribute.getId() ) ) );

        Set<String> vals = typesVals.get( Strings.toLowerCaseAscii( attribute.getId() ) );

        for ( Value value : attribute )
        {
            assertTrue( vals.contains( value.getString() ) );

            vals.remove( value.getString() );
        }

        attribute = entry.get( "attrs" );

        assertTrue( expectedTypes.contains( Strings.toLowerCaseAscii( attribute.getId() ) ) );

        vals = typesVals.get( Strings.toLowerCaseAscii( attribute.getId() ) );

        for ( Value value : attribute )
        {
            assertTrue( vals.contains( value.getString() ) );

            vals.remove( value.getString() );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        AddRequest request = new AddRequestImpl();
        request.setEntry( addRequest.getEntry() );
        request.setMessageId( addRequest.getMessageId() );

        LdapEncoder.encodeMessage( buffer, codec, request );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a AddRequest with a null body
     */
    @Test
    public void testDecodeAddRequestNullBody()
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x68, 0x00            // CHOICE { ..., addRequest AddRequest, ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a AddRequest with a null entry
     */
    @Test
    public void testDecodeAddRequestNullEntry()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x39 );

        stream.put( new byte[]
            {
                0x30, 0x37,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x68, 0x26,                   // CHOICE { ..., addRequest AddRequest, ...
                                                // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x00,                 // entry LDAPDN,
                                                // attributes AttributeList }
                    0x30, 0x2E,                 // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x0c,               // attribute 1
                        0x04, 0x01,
                          'l',                  // type AttributeDescription,
                        0x31, 0x07,             // vals SET OF AttributeValue }
                          0x04, 0x05,
                            'P', 'a', 'r', 'i', 's',
                      0x30, 0x1E,               // attribute 2
                        0x04, 0x05,             // type AttributeDescription,
                          'a', 't', 't', 'r', 's',
                        0x31, 0x15,             // vals SET OF AttributeValue }
                          0x04, 0x05,
                            't', 'e', 's', 't', '1',
                          0x04, 0x05,
                            't', 'e', 's', 't', '2',
                          0x04, 0x05,
                            't', 'e', 's', 't', '3'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, container );
            }
            catch ( DecoderException de )
            {
                assertTrue( de instanceof ResponseCarryingException );
                Message response = ( ( ResponseCarryingException ) de ).getResponse();
                assertTrue( response instanceof AddResponseImpl );
                assertEquals( ResultCodeEnum.NAMING_VIOLATION, ( ( AddResponseImpl ) response ).getLdapResult()
                    .getResultCode() );
    
                throw de;
            }
        } );
    }


    /**
     * Test the decoding of a AddRequest
     */
    @Test
    public void testDecodeAddRequestbadDN()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x59 );

        stream.put( new byte[]
            {
                0x30, 0x57,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x68, 0x52,                   // CHOICE { ..., addRequest AddRequest, ...
                                                // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,                 // entry LDAPDN,
                      'c', 'n', ':', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                                // attributes AttributeList }
                    0x30, 0x2E,                 // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x0c,               // attribute 1
                        0x04, 0x01,
                         'l',                   // type AttributeDescription,
                      0x31, 0x07,               // vals SET OF AttributeValue }
                        0x04, 0x05,
                          'P', 'a', 'r', 'i', 's',
                    0x30, 0x1E,                 // attribute 2
                      0x04, 0x05,               // type AttributeDescription,
                        'a', 't', 't', 'r', 's',
                      0x31, 0x15,               // vals SET OF AttributeValue }
                        0x04, 0x05,
                          't', 'e', 's', 't', '1',
                        0x04, 0x05,
                          't', 'e', 's', 't', '2',
                        0x04, 0x05,
                          't', 'e', 's', 't', '3'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, container );
            }
            catch ( DecoderException de )
            {
                assertTrue( de instanceof ResponseCarryingException );
                Message response = ( ( ResponseCarryingException ) de ).getResponse();
                assertTrue( response instanceof AddResponseImpl );
                assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( AddResponseImpl ) response ).getLdapResult()
                    .getResultCode() );
    
                throw de;
            }
        } );
    }


    /**
     * Test the decoding of a AddRequest with a null attributeList
     */
    @Test
    public void testDecodeAddRequestNullAttributes()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2B );

        stream.put( new byte[]
            {
                0x30, 0x29,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x68, 0x24,               // CHOICE { ..., addRequest AddRequest, ...
                                            // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                            // attributes AttributeList }
                    0x30, 0x00              // AttributeList ::= SEQUENCE OF SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList
     */
    @Test
    public void testDecodeAddRequestNullAttributeList()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2D );

        stream.put( new byte[]
            {
                0x30, 0x2B,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x68, 0x26,               // CHOICE { ..., addRequest AddRequest, ...
                                            // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                            // attributes AttributeList }
                    0x30, 0x02,             // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList
     */
    @Test
    public void testDecodeAddRequestNullType()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2F );

        stream.put( new byte[]
            {
                0x30, 0x2D,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x68, 0x28,               // CHOICE { ..., addRequest AddRequest, ...
                                            // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                            // attributes AttributeList }
                    0x30, 0x04,             // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x02,           // attribute 1
                        0x04, 0x00          // type AttributeDescription,
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, container );
            }
            catch ( DecoderException de )
            {
                assertTrue( de instanceof ResponseCarryingException );
                Message response = ( ( ResponseCarryingException ) de ).getResponse();
                assertTrue( response instanceof AddResponseImpl );
                assertEquals( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, ( ( AddResponseImpl ) response ).getLdapResult()
                    .getResultCode() );
    
                throw de;
            }
        } );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList
     */
    @Test
    public void testDecodeAddRequestNoVals()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x30 );

        stream.put( new byte[]
            {
                0x30, 0x2E,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x68, 0x29,               // CHOICE { ..., addRequest AddRequest, ...
                                            // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                            // attributes AttributeList }
                    0x30, 0x05,             // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x03,           // attribute 1
                        0x04, 0x01,         // type AttributeDescription,
                          'A'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList
     */
    @Test
    public void testDecodeAddRequestNullVals()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x32 );

        stream.put( new byte[]
            {
                0x30, 0x30,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x68, 0x2B,                   // CHOICE { ..., addRequest AddRequest, ...
                                                // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,                 // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                                // attributes AttributeList }
                    0x30, 0x07,                 // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x05,               // attribute 1
                        0x04, 0x01,             // type AttributeDescription,
                          'A',
                        0x31, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, container );
        } );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeAddRequestEmptyAttributeValue() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x34 );

        stream.put( new byte[]
            {
                0x30, 0x32,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x68, 0x2D,                   // CHOICE { ..., addRequest AddRequest, ...
                                                // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    0x04, 0x20,                 // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                                // attributes AttributeList }
                    0x30, 0x09,                 // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x07,               // attribute 1
                        0x04, 0x01,
                          'l',                  // type AttributeDescription,
                        0x31, 0x02,
                          0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        Asn1Decoder.decode( stream, container );

        AddRequest addRequest = container.getMessage();

        // Check the decoded message
        assertEquals( 1, addRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", addRequest.getEntryDn().toString() );

        Entry entry = addRequest.getEntry();

        assertEquals( 1, entry.size() );

        Attribute attribute = entry.get( "l" );

        assertEquals( "l", Strings.toLowerCaseAscii( attribute.getId() ) );

        for ( Value value : attribute )
        {
            assertEquals( "", value.getString() );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        AddRequest request = new AddRequestImpl();
        request.setEntry( addRequest.getEntry() );
        request.setMessageId( addRequest.getMessageId() );

        LdapEncoder.encodeMessage( buffer, codec, request );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a AddRequest with a empty attributeList and a
     * control
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeAddRequestEmptyAttributeValueWithControl() throws  DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x51 );

        stream.put( new byte[]
            {
                0x30, 0x4F, // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01, // messageID MessageID
                  0x68, 0x2D, // CHOICE { ..., addRequest AddRequest, ...
                    // AddRequest ::= [APPLICATION 8] SEQUENCE {
                    // entry LDAPDN,
                    0x04, 0x20,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    // attributes AttributeList }
                    0x30, 0x09, // AttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x07, // attribute 1
                        0x04, 0x01,
                          'l', // type AttributeDescription,
                      0x31, 0x02,
                        0x04, 0x00,
                    ( byte ) 0xA0, 0x1B, // A control (ManageDsaIT)
                      0x30, 0x19,
                        0x04, 0x17,
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1',  '.', '1', '1', '3', '7', '3', '0',
                          '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddRequest> container = new LdapMessageContainer<>( codec );

        // Decode a AddRequest message
        Asn1Decoder.decode( stream, container );

        AddRequest addRequest = container.getMessage();

        // Check the decoded message
        assertEquals( 1, addRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", addRequest.getEntryDn().toString() );

        Entry entry = addRequest.getEntry();

        assertEquals( 1, entry.size() );

        Attribute attribute = entry.get( "l" );

        assertEquals( "l", Strings.toLowerCaseAscii( attribute.getId() ) );

        for ( Value value : attribute )
        {
            assertEquals( "", value.getString() );
        }

        // Check the Control
        Map<String, Control> controls = addRequest.getControls();

        assertEquals( 1, controls.size() );

        assertTrue( addRequest.hasControl( "2.16.840.1.113730.3.4.2" ) );

        Control control = controls.get( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        AddRequest request = new AddRequestImpl();
        request.setEntry( addRequest.getEntry() );
        request.setMessageId( addRequest.getMessageId() );
        request.addControl( new ManageDsaITImpl() );

        LdapEncoder.encodeMessage( buffer, codec, request );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
        
        // Check encode reverse
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        AddRequest request2 = new AddRequestImpl();
        request2.setEntry( addRequest.getEntry() );
        request2.setMessageId( addRequest.getMessageId() );
        request2.addControl( new ManageDsaITImpl() );

        LdapEncoder.encodeMessage( asn1Buffer, codec, request2 );

        assertArrayEquals( stream.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test that encoding and decoding of an add request with 10k attributes and 10k values
     * succeeds without StackOverflowError (DIRAPI-368, DIRSERVER-2340).
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testEncodeDecodeLarge() throws DecoderException, EncoderException, LdapException
    {
        Asn1Buffer buffer = new Asn1Buffer();

        AddRequest originalAddRequest = new AddRequestImpl();
        originalAddRequest.setMessageId( 3 );
        Dn dn = new Dn( "cn=test,ou=users,ou=system" );
        originalAddRequest.setEntryDn( dn );
        Entry entry = new DefaultEntry( dn );
        for ( int attributeIndex = 0; attributeIndex < 100000; attributeIndex++ )
        {
            entry.add( "objectclass" + attributeIndex, "top", "person" );
        }
        String[] values = IntStream.range( 0, 100000 ).boxed().map( i -> "value" + i ).toArray( String[]::new );
        entry.add( "objectclass", values );
        originalAddRequest.setEntry( entry );

        LdapEncoder.encodeMessage( buffer, codec, originalAddRequest );

        LdapMessageContainer<AddRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( buffer.getBytes(), ldapMessageContainer );

        AddRequest decodedAddRequest = ldapMessageContainer.getMessage();

        assertEquals( originalAddRequest, decodedAddRequest );
    }

}
