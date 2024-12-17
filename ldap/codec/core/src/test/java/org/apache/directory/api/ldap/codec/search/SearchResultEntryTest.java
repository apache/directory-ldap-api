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
package org.apache.directory.api.ldap.codec.search;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.IntStream;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultEntryImpl;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the SearchResultEntry codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SearchResultEntryTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a SearchResultEntry
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntrySuccess() throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x50 );

        stream.put( new byte[]
            {
                0x30, 0x4e,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x49,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x2a,
                      0x30, 0x28,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x19,             // vals SET OF AttributeValue }
                          0x04, 0x03,           // AttributeValue ::= OCTET STRING
                            't', 'o', 'p',
                          0x04, 0x12,           // AttributeValue ::= OCTET STRING
                            'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a', 't', 'i', 'o', 'n', 'a', 'l', 'U', 'n', 'i', 't',
             } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertTrue( attribute.contains( "top" ) );
            assertTrue( attribute.contains( "organizationalUnit" ) );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertTrue( Arrays.equals( stream.array(), buffer.getBytes().array() ) );
    }

    /**
     * Test the decoding of a SearchResultEntry
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntry2AttrsSuccess() throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x7b );

        stream.put( new byte[]
            {
                0x30, 0x79,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x74,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x55,
                      0x30, 0x28,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x19,             // vals SET OF AttributeValue }
                          0x04, 0x03,           // AttributeValue ::= OCTET STRING
                            't', 'o', 'p',
                          0x04, 0x12,           // AttributeValue ::= OCTET STRING
                            'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a', 't', 'i', 'o', 'n', 'a', 'l', 'U', 'n', 'i', 't',
                      0x30, 0x29,
                        0x04, 0x0c,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's', '2',
                        0x31, 0x19,             // vals SET OF AttributeValue }
                          0x04, 0x03,           // AttributeValue ::= OCTET STRING
                            't', 'o', 'p',
                          0x04, 0x12,           // AttributeValue ::= OCTET STRING
                            'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a', 't', 'i', 'o', 'n', 'a', 'l', 'U', 'n', 'i', 't'
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 2, entry.size() );

        String[] expectedAttributes = new String[]
            { "objectClass", "objectClass2" };

        for ( int i = 0; i < expectedAttributes.length; i++ )
        {
            Attribute attribute = entry.get( expectedAttributes[i] );

            assertEquals(
                Strings.toLowerCaseAscii( expectedAttributes[i] ),
                Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertTrue( attribute.contains( "top" ) );
            assertTrue( attribute.contains( "organizationalUnit" ) );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        // We can't compare the encodings, the order of the attributes has
        // changed
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer2 =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( result, ldapMessageContainer2 );

        assertEquals( searchResultEntry.getEntry(), ldapMessageContainer2.getMessage().getEntry() );
        assertEquals( searchResultEntry.getObjectName(), ldapMessageContainer2.getMessage().getObjectName() );
    }


    /**
     * Test the decoding of a SearchResultEntry with more bytes to be decoded at
     * the end
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntrySuccessWithFollowingMessage() throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x66 );

        stream.put( new byte[]
            {
                0x30, 0x5F,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x02,             // messageID MessageID
                  0x64, 0x5A,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x13,
                      'u', 'i', 'd', '=', 'a', 'd', 'm', 'i', 'n', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                                                // attributes PartialAttributeList }
                    0x30, 0x43,                 // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                      0x30, 0x41,
                        0x04, 0x0B,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x32,             // vals SET OF AttributeValue }
                          0x04, 0x0D,           // AttributeValue ::= OCTET STRING
                            'i', 'n', 'e', 't', 'O', 'r', 'g', 'P', 'e', 'r', 's', 'o', 'n',
                          0x04, 0x14,           // AttributeValue ::= OCTET STRING
                            'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a',
                            't', 'i', 'o', 'n', 'a', 'l', 'P', 'e',
                            'r', 's', 'o', 'n',
                          0x04, 0x06,           // AttributeValue ::= OCTET STRING
                            'p', 'e', 'r', 's', 'o', 'n',
                          0x04, 0x03,           // AttributeValue ::= OCTET STRING
                            't', 'o', 'p',
                0x30, 0x45, // Start of the next message
                  0x02, 0x01, 0x03 // messageID MessageID ...
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 2, searchResultEntry.getMessageId() );
        assertEquals( "uid=admin,ou=system", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertTrue( attribute.contains( "top" ) );
            assertTrue( attribute.contains( "person" ) );
            assertTrue( attribute.contains( "organizationalPerson" ) );
            assertTrue( attribute.contains( "inetOrgPerson" ) );
        }

        // Check that the next bytes is the first of the next PDU
        assertEquals( 0x30, stream.get( stream.position() ) );
        assertEquals( 0x45, stream.get( stream.position() + 1 ) );
        assertEquals( 0x02, stream.get( stream.position() + 2 ) );
        assertEquals( 0x01, stream.get( stream.position() + 3 ) );
        assertEquals( 0x03, stream.get( stream.position() + 4 ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        // We can't compare the encodings, the order of the attributes has
        // changed
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer2 =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( buffer.getBytes(), ldapMessageContainer2 );

        assertEquals( searchResultEntry.getEntry(), ldapMessageContainer2.getMessage().getEntry() );
        assertEquals( searchResultEntry.getObjectName(), ldapMessageContainer2.getMessage().getObjectName() );
    }


    // Defensive tests

    /**
     * Test the decoding of an empty SearchResultEntry
     */
    @Test
    public void testDecodeSearchResultEntryEmpty()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {

                0x30, 0x05,                 // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,           // messageID MessageID
                  0x64, 0x00                // CHOICE { ..., searchResEntry SearchResultEntry,
                                            // ...
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of an SearchResultEntry with an empty object name
     */
    @Test
    public void testDecodeSearchResultEntryEmptyObjectName()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            {
                0x30, 0x07,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x64, 0x02,               // CHOICE { ..., searchResEntry SearchResultEntry,
                                            // ...
                                            // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                            // objectName LDAPDN,
                    0x04, 0x00

            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of an SearchResultEntry with an object name alone
     */
    @Test
    public void testDecodeSearchResultEntryObjectNameAlone()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x24 );

        stream.put( new byte[]
            {
                0x30, 0x22,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x1D,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1B,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm'
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of an SearchResultEntry with an empty attributes
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyAttributes() throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x26 );

        stream.put( new byte[]
            {
                0x30, 0x24,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x1F,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1B,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 0, entry.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an SearchResultEntry with an empty attributes list
     */
    @Test
    public void testDecodeSearchResultEntryEmptyAttributeList()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x28 );

        stream.put( new byte[]
            {
                0x30, 0x26,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x21,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1B,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x02,
                      0x30, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of an SearchResultEntry with an empty attributes list
     * with controls
     */
    @Test
    public void testDecodeSearchResultEntryEmptyAttributeListWithControls()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x45 );

        stream.put( new byte[]
            {
                0x30, 0x43,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                   0x64, 0x21,                  // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1B,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x02,
                      0x30, 0x00,
                    ( byte ) 0xA0, 0x1B,        // A control
                      0x30, 0x19,
                        0x04, 0x17,
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                          '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchResultEntry with an empty type
     */
    @Test
    public void testDecodeSearchResultEntryEmptyType()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x2A );

        stream.put( new byte[]
            {
                0x30, 0x28,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x23,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x04,
                      0x30, 0x02,
                        0x04, 0x00              // type AttributeDescription,
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchResultEntry with a type alone
     */
    @Test
    public void testDecodeSearchResultEntryTypeAlone()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );

        stream.put( new byte[]
            {
                0x30, 0x33,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x2E,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x0F,
                      0x30, 0x0D,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's'
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchResultEntry with an empty vals
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyVals() throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x37 );

        stream.put( new byte[]
            {
                0x30, 0x35,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x30,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x11,
                      0x30, 0x0F,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );
            assertEquals( 0, attribute.size() );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a SearchResultEntry with two empty vals
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyVals2() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x48 );

        stream.put( new byte[]
            {
                0x30, 0x46,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x41,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x22,
                      0x30, 0x0F,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x00,
                      0x30, 0x0F,
                        0x04, 0x0b,           // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 'z', 'z',
                        0x31, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 2, entry.size() );

        Attribute attribute = entry.get( "objectclass" );
        assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );
        assertEquals( 0, attribute.size() );

        attribute = entry.get( "objectclazz" );
        assertEquals( Strings.toLowerCaseAscii( "objectClazz" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );
        assertEquals( 0, attribute.size() );


        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a SearchResultEntry with an empty vals with controls
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyValsWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x5B );

        stream.put( new byte[]
            {
                0x30, 0x59,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x30,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x11,
                      0x30, 0x0F,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x00,
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

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertEquals( 0, attribute.size() );
        }

        // Check the Control
        Map<String, Control> controls = searchResultEntry.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );
        assertTrue( control instanceof EntryChange );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a SearchResultEntry with an empty attribute value
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     * @throws LdapException If the test failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyAttributeValue()
        throws DecoderException, EncoderException, LdapException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x39 );

        stream.put( new byte[]
            {
                0x30, 0x37,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x32,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x13,
                      0x30, 0x11,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x31, 0x02,               // vals SET OF AttributeValue }
                        0x04, 0x00              // AttributeValue ::= OCTET STRING
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertTrue( attribute.contains( "" ) );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a SearchResultEntry with an empty attribute value
     * with controls
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeSearchResultEntryEmptyAttributeValueWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x5D );

        stream.put( new byte[]
            {
                0x30, 0x5B,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x64, 0x32,                   // CHOICE { ..., searchResEntry SearchResultEntry,
                                                // ...
                                                // SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
                                                // objectName LDAPDN,
                    0x04, 0x1b,
                      'o', 'u', '=', 'c', 'o', 'n', 't', 'a', 'c', 't', 's', ',',
                      'd', 'c', '=', 'i', 'k', 't', 'e', 'k', ',', 'd', 'c', '=', 'c', 'o', 'm',
                                                // attributes PartialAttributeList }
                                                // PartialAttributeList ::= SEQUENCE OF SEQUENCE {
                    0x30, 0x13,
                      0x30, 0x11,
                        0x04, 0x0b,             // type AttributeDescription,
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                        0x31, 0x02,             // vals SET OF AttributeValue }
                          0x04, 0x00,           // AttributeValue ::= OCTET STRING
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

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchResultEntry> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchResultEntry searchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultEntry.getMessageId() );
        assertEquals( "ou=contacts,dc=iktek,dc=com", searchResultEntry.getObjectName().toString() );

        Entry entry = searchResultEntry.getEntry();

        assertEquals( 1, entry.size() );

        for ( int i = 0; i < entry.size(); i++ )
        {
            Attribute attribute = entry.get( "objectclass" );

            assertEquals( Strings.toLowerCaseAscii( "objectClass" ), Strings.toLowerCaseAscii( attribute.getUpId() ) );

            assertTrue( attribute.contains( "" ) );
        }

        // Check the Control
        Map<String, Control> controls = searchResultEntry.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );
        assertTrue( control instanceof EntryChange );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, searchResultEntry );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test that encoding and decoding of a search result entry with 10k attributes and 10k values
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

        SearchResultEntry originalSearchResultEntry = new SearchResultEntryImpl();
        originalSearchResultEntry.setMessageId( 3 );
        Dn dn = new Dn( "cn=test,ou=users,ou=system" );
        originalSearchResultEntry.setObjectName( dn );
        Entry entry = new DefaultEntry( dn );
        for ( int attributeIndex = 0; attributeIndex < 100000; attributeIndex++ )
        {
            entry.add( "objectclass" + attributeIndex, "top", "person" );
        }
        String[] values = IntStream.range( 0, 100000 ).boxed().map( i -> "value" + i ).toArray( String[]::new );
        entry.add( "objectclass", values );
        originalSearchResultEntry.setEntry( entry );

        LdapEncoder.encodeMessage( buffer, codec, originalSearchResultEntry );

        LdapMessageContainer<SearchResultEntry> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( buffer.getBytes(), ldapMessageContainer );

        SearchResultEntry decodedSearchResultEntry = ldapMessageContainer.getMessage();

        assertEquals( originalSearchResultEntry, decodedSearchResultEntry );
    }

}
