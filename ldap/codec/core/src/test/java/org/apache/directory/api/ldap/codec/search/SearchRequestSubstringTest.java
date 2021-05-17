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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.OidNormalizer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * A test case for SearchRequest messages
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SearchRequestSubstringTest extends AbstractCodecServiceTest
{
    /** An oid normalizer map */
    static Map<String, OidNormalizer> oids = new HashMap<String, OidNormalizer>();


    @BeforeAll
    public static void setUp() throws Exception
    {
        // DC normalizer
        OidNormalizer dcOidNormalizer = new OidNormalizer( "dc", new DeepTrimToLowerNormalizer(
            SchemaConstants.DOMAIN_COMPONENT_AT_OID ) );

        oids.put( "dc", dcOidNormalizer );
        oids.put( "domaincomponent", dcOidNormalizer );
        oids.put( "0.9.2342.19200300.100.1.25", dcOidNormalizer );

        // OU normalizer
        OidNormalizer ouOidNormalizer = new OidNormalizer( "ou", new DeepTrimToLowerNormalizer(
            SchemaConstants.OU_AT_OID ) );

        oids.put( "ou", ouOidNormalizer );
        oids.put( "organizationalUnitName", ouOidNormalizer );
        oids.put( "2.5.4.11", ouOidNormalizer );

        // ObjectClass normalizer
        OidNormalizer objectClassOidNormalizer = new OidNormalizer( "objectClass", new DeepTrimToLowerNormalizer(
            SchemaConstants.OBJECT_CLASS_AT_OID ) );

        oids.put( "objectclass", objectClassOidNormalizer );
        oids.put( "2.5.4.0", objectClassOidNormalizer );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=t*)
     */
    @Test
    public void testDecodeSearchRequestSubstringInitialAny() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x64 );
        stream.put( new byte[]
            {
                0x30, 0x62,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x5D,                           //      CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x12,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x03,
                        ( byte ) 0x80, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( "t", substringNode.getInitial() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=t*) With controls
     */
    @Test
    public void testDecodeSearchRequestSubstringInitialAnyWithControls()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x0081 );
        stream.put( new byte[]
            {
                0x30, 0x7F,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x5D,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x12,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x03,
                        ( byte ) 0x80, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',        // AttributeDescription ::= LDAPString
                    ( byte ) 0xA0, 0x1B,                // A control
                      0x30, 0x19,
                        0x04, 0x17,                     // control
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                          '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2',
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( "t", substringNode.getInitial() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check the Control
        Map<String, Control> controls = searchRequest.getControls();

        assertEquals( 1, controls.size() );

        Control control = searchRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertTrue( control instanceof ManageDsaIT );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * any filter : (objectclass=*t*)
     */
    @Test
    public void testDecodeSearchRequestSubstringAny() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x64 );
        stream.put( new byte[]
            {
                0x30, 0x62,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID
                  0x63, 0x5D,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                    // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,// sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,// timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x12,            // Filter ::= CHOICE {
                                                    // substrings [4] SubstringFilter
                                                    // }
                                                    // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x03,
                        ( byte ) 0x81, 0x01,
                          't',
                    0x30, 0x15,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'     // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( null, substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );
        assertEquals( null, substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=*t*t)
     */
    @Test
    public void testDecodeSearchRequestSubstringAnyFinal() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x67 );
        stream.put( new byte[]
            {
                0x30, 0x65,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x60,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x15,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x06,
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x82, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( null, substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );
        assertEquals( "t", substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=t*t*t)
     */
    @Test
    public void testDecodeSearchRequestSubstringInitialAnyFinal()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x6A );
        stream.put( new byte[]
            {
                0x30, 0x68,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x63,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x18,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x09,
                        ( byte ) 0x80, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x82, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( "t", substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );
        assertEquals( "t", substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=t*t*)
     */
    @Test
    public void testDecodeSearchRequestSubstringInitialAnyAnyFinal()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x67 );
        stream.put( new byte[]
            {
                0x30, 0x65,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x60,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x15,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x06,
                        ( byte ) 0x80, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( "t", substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=*t*t*t)
     */
    @Test
    public void testDecodeSearchRequestSubstringAnyAnyFinal() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x6A );
        stream.put( new byte[]
            {
                0x30, 0x68,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x63,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                                                        // filter Filter,
                    ( byte ) 0xA4, 0x18,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x09,
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x82, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( null, substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );
        assertEquals( "t", substringNode.getAny().get( 1 ) );
        assertEquals( "t", substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check the encoding
        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertTrue( Arrays.equals( stream.array(), buffer.getBytes().array() ) );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=t*)
     */
    @Test
    public void testDecodeSearchRequestSubstringInitialAnyAny() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x67 );
        stream.put( new byte[]
            {
                0x30, 0x65,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x60,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x15,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x06,
                        ( byte ) 0x80, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          '*',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'     // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( "t", substringNode.getInitial() );
        assertEquals( "*", substringNode.getAny().get( 0 ) );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=*t*t*t*)
     */
    @Test
    public void testDecodeSearchRequestSubstringAnyAnyAny() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x6A );
        stream.put( new byte[]
            {
                0x30, 0x68,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x63,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x18,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x09,
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          't',
                        ( byte ) 0x81, 0x01,
                          't',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( null, substringNode.getInitial() );
        assertEquals( "t", substringNode.getAny().get( 0 ) );
        assertEquals( "t", substringNode.getAny().get( 1 ) );
        assertEquals( "t", substringNode.getAny().get( 2 ) );
        assertEquals( null, substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a substring filter. Test the
     * initial filter : (objectclass=*Amos)
     */
    @Test
    public void testDecodeSearchRequestSubstringFinal() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x67 );
        stream.put( new byte[]
            {
                0x30, 0x65,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID
                  0x63, 0x60,                           // CHOICE { ..., searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x15,                // Filter ::= CHOICE {
                                                        // substrings [4] SubstringFilter
                                                        // }
                                                        // SubstringFilter ::= SEQUENCE {
                      0x04, 0x0B,
                        'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                      0x30, 0x06,
                        ( byte ) 0x82, 0x04,
                          'A', 'm', 'o', 's',
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2'         // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        ExprNode node = searchRequest.getFilter();
        SubstringNode substringNode = ( SubstringNode ) node;
        assertNotNull( substringNode );

        assertEquals( "objectclass", substringNode.getAttribute() );
        assertEquals( null, substringNode.getInitial() );
        assertEquals( 0, substringNode.getAny().size() );
        assertEquals( "Amos", substringNode.getFinal() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        for ( String attribute : attributes )
        {
            assertNotNull( attribute );
        }

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with an empty Substring filter
     */
    @Test
    public void testDecodeSearchRequestEmptySubstringFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3B,
                  0x02, 0x01, 0x04,             // messageID
                  0x63, 0x36,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                // baseObject (0),
                                                // singleLevel (1),
                                                // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                // neverDerefAliases (0),
                                                // derefInSearching (1),
                                                // derefFindingBaseObj (2),
                                                // derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x00,
                    0x30, 0x02,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterEmptyType() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3D,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x38,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x02,
                      0x04, 0x00,
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterNoSubstrings() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x41,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x3D,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x06,
                      0x04, 0x04,
                       't', 'e', 's', 't',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterEmptySubstrings() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x43,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x3E,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x08,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x00,
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring Initial
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterEmptyInitial() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x45,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x40,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0A,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x02,
                        ( byte ) 0x80, 0x00,
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring Any
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterEmptyAny() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x45,
                  0x02, 0x01, 0x04,                     // messageID
                  0x63, 0x40,
                    0x04, 0x1F,                         // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        // baseObject (0),
                                                        // singleLevel (1),
                                                        // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        // neverDerefAliases (0),
                                                        // derefInSearching (1),
                                                        // derefFindingBaseObj (2),
                                                        // derefAlways (3) },
                    0x02, 0x01, 0x00,                   // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,                   // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0A,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x02,
                        ( byte ) 0x81, 0x00,
                    0x30, 0x02,                         // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter and an empty
     * Substring Initial
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterEmptyFinal() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x45,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x40,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0A,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x02,
                        ( byte ) 0x82, 0x00,
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter Any before
     * initial
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterAnyInitial() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x49,
                  0x02, 0x01, 0x01,                 // messageID
                  0x63, 0x44,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0E,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x06,
                        ( byte ) 0x81, 0x01,
                          'a',
                        ( byte ) 0x80, 0x01,
                          'b',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter Final before
     * initial
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterFinalInitial() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x49,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x44,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0E,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x06,
                        ( byte ) 0x82, 0x01,
                          'a',
                        ( byte ) 0x80, 0x01,
                          'b',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter Final before
     * any
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterFinalAny() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x49,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x44,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0E,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x06,
                        ( byte ) 0x82, 0x01,
                          'a',
                        ( byte ) 0x81, 0x01,
                          'b',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter Two initials
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterTwoInitials() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x49,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x44,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0E,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x06,
                        ( byte ) 0x80, 0x01,
                          'a',
                        ( byte ) 0x80, 0x01,
                          'b',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a SearchRequest with a Substring filter Two finals
     */
    @Test
    public void testDecodeSearchRequestSubstringFilterTwoFinals() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x49,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x44,
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE) filter Filter,
                    ( byte ) 0xA4, 0x0E,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x30, 0x06,
                        ( byte ) 0x82, 0x01,
                          'a',
                        ( byte ) 0x82, 0x01,
                          'b',
                    0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }
}
