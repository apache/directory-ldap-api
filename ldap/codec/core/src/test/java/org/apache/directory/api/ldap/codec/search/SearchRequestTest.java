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
package org.apache.directory.api.ldap.codec.search;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.ApproximateNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.LessEqNode;
import org.apache.directory.api.ldap.model.filter.NotNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchResultDoneImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.Subentries;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.OidNormalizer;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * A test case for SearchRequest messages
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SearchRequestTest extends AbstractCodecServiceTest
{
    /** An oid normalizer map */
    static Map<String, OidNormalizer> oids = new HashMap<String, OidNormalizer>();


    @Before
    public void setUp() throws Exception
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
     * Test the decoding of a SearchRequest with no controls. The search filter
     * is : (&(|(objectclass=top)(ou=contacts))(!(objectclass=ttt)))
     */
    @Test
    public void testDecodeSearchRequestGlobalNoControls() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x90 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8D,     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x87,   // CHOICE { ...,
                                                        // searchRequest SearchRequest, ...
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
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE)
                                                        // filter Filter,
                    ( byte ) 0xA0, 0x3C,                // Filter ::= CHOICE {
                                                        // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,              // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,            // equalityMatch [3]
                                                        // Assertion,
                                                        // Assertion ::= SEQUENCE {
                                                        // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,            // equalityMatch [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',                   // attributeDesc AttributeDescription (LDAPString),
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,              // not [2] Filter,
                        ( byte ) 0xA3, 0x12,            // equalityMatch [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                                                        // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 't', 't',
                                                        // attributes AttributeDescriptionList }
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',        // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (& (...
        ExprNode node = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) node;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();

        // (& (| (...
        assertEquals( 2, andNodes.size() );
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        // (& (| (obectclass=top) (...
        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) orNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "top", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (...
        equalityNode = ( EqualityNode<?> ) orNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "ou", equalityNode.getAttribute() );
        assertEquals( "contacts", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (! ...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (& (| (objectclass=top) (ou=contacts) ) (! (objectclass=ttt) ) )
        equalityNode = ( EqualityNode<?> ) notNode.getFirstChild();
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "ttt", equalityNode.getValue().getString() );

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
     * Test the decoding of a SearchRequest with no controls. Test the various
     * types of filter : >=, <=, ~= The search filter is :
     * (&(|(objectclass~=top)(ou<=contacts))(!(objectclass>=ttt)))
     */
    @Test
    public void testDecodeSearchRequestCompareFiltersNoControls()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x90 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8D,     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x87,   //     CHOICE { ...,
                                                        //         searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        //         baseObject   (0),
                                                        //         singleLevel  (1),
                                                        //         wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        //         neverDerefAliases (0),
                                                        //         derefInSearching (1),
                                                        //         derefFindingBaseObj (2),
                                                        //         derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    //     sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    //     timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE)
                                                        //     filter Filter,
                    ( byte ) 0xA0, 0x3C,                // Filter ::= CHOICE {
                                                        //      and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,              //      or [1] SET of Filter,
                        ( byte ) 0xA8, 0x12,            //      approxMatch [8]
                                                        // Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA6, 0x0E,            // lessOrEqual [3] Assertion,
                          0x04, 0x02,
                            'o', 'u',                   // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,              // not [2] Filter,
                        ( byte ) 0xA5, 0x12,            // greaterOrEqual [5] Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,
                            't', 't', 't',
                                                        // attributes AttributeDescriptionList }
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF
                                                        // AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',        // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (& (...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();

        // (& (| (...
        assertEquals( 2, andNodes.size() );
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        // (& (| (objectclass~=top) (...
        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );
        ApproximateNode<?> approxNode = ( ApproximateNode<?> ) orNodes.get( 0 );
        assertNotNull( approxNode );

        assertEquals( "objectclass", approxNode.getAttribute() );
        assertEquals( "top", approxNode.getValue().getString() );

        // (& (| (objectclass~=top) (ou<=contacts) ) (...
        LessEqNode<?> lessOrEqualNode = ( LessEqNode<?> ) orNodes.get( 1 );
        assertNotNull( lessOrEqualNode );

        assertEquals( "ou", lessOrEqualNode.getAttribute() );
        assertEquals( "contacts", lessOrEqualNode.getValue().getString() );

        // (& (| (objectclass~=top) (ou<=contacts) ) (! ...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (& (| (objectclass~=top) (ou<=contacts) ) (! (objectclass>=ttt) ) )
        GreaterEqNode<?> greaterOrEqual = ( GreaterEqNode<?> ) notNode.getFirstChild();
        assertNotNull( greaterOrEqual );

        assertEquals( "objectclass", greaterOrEqual.getAttribute() );
        assertEquals( "ttt", greaterOrEqual.getValue().getString() );

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
     * Test the decoding of a SearchRequest with no controls. Test the present
     * filter : =* The search filter is :
     * (&(|(objectclass=*)(ou=*))(!(objectclass>=ttt)))
     */
    @Test
    public void testDecodeSearchRequestPresentNoControls() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x7B );
        stream.put( new byte[]
            {
                0x30, 0x79,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x74,                   // CHOICE { ..., searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
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
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,    // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x29,        // Filter ::= CHOICE {
                                                // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x11,      // or [1] SET of Filter,
                        ( byte ) 0x87, 0x0B,    // present [7] AttributeDescription,
                                                // AttributeDescription ::= LDAPString
                          'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                // assertionValue AssertionValue (OCTET STRING) }
                        ( byte ) 0x87, 0x02,
                          'o', 'u',             // present [7]
                                                // AttributeDescription,
                                                // AttributeDescription ::= LDAPString
                      ( byte ) 0xA2, 0x14,      // not [2] Filter,
                        ( byte ) 0xA5, 0x12,    // greaterOrEqual [5]
                                                // Assertion,
                                                // Assertion ::= SEQUENCE {
                                                // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 't', 't',
                                                // attributes AttributeDescriptionList }
                    0x30,  0x15,                // AttributeDescriptionList ::= SEQUENCE OF
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',// AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',// AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',// AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (& (...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();

        // (& (| (...
        assertEquals( 2, andNodes.size() );
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        // (& (| (objectclass=*) (...
        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );

        PresenceNode presenceNode = ( PresenceNode ) orNodes.get( 0 );
        assertNotNull( presenceNode );

        assertEquals( "objectclass", presenceNode.getAttribute() );

        // (& (| (objectclass=*) (ou=*) ) (...
        presenceNode = ( PresenceNode ) orNodes.get( 1 );
        assertNotNull( presenceNode );

        assertEquals( "ou", presenceNode.getAttribute() );

        // (& (| (objectclass=*) (ou=*) ) (! ...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (& (| (objectclass=*) (ou=*) ) (! (objectclass>=ttt) ) )
        GreaterEqNode<?> greaterOrEqual = ( GreaterEqNode<?> ) notNode.getFirstChild();
        assertNotNull( greaterOrEqual );

        assertEquals( "objectclass", greaterOrEqual.getAttribute() );
        assertEquals( "ttt", greaterOrEqual.getValue().getString() );

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
     * Test the decoding of a SearchRequest with no attributes. The search
     * filter is : (objectclass=*)
     */
    @Test
    public void testDecodeSearchRequestNoAttributes() throws DecoderException, EncoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x40 );
        stream.put( new byte[]
            {
                0x30, 0x37,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x03,         // messageID MessageID
                  0x63, 0x32,               // CHOICE { ..., searchRequest SearchRequest, ...
                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x12,             // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                                            // baseObject (0),
                                            // singleLevel (1),
                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,       // derefAliases ENUMERATED {
                                            // neverDerefAliases (0),
                                            // derefInSearching (1),
                                            // derefFindingBaseObj (2),
                                            // derefAlways (3) },
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,       // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,       // typesOnly BOOLEAN, (FALSE)
                                            // filter Filter,
                                            // Filter ::= CHOICE {
                    ( byte ) 0x87, 0x0B,    // present [7] AttributeDescription,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                                            // attributes AttributeDescriptionList }
                    0x30, 0x00,             // AttributeDescriptionList ::= SEQUENCE OF
                                            // AttributeDescription
                0x00, 0x00,                 // Some trailing 00, useless.
                0x00, 0x00, 0x00, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 3, searchRequest.getMessageId() );
        assertEquals( "ou=users,ou=system", searchRequest.getBase().toString() );
        assertEquals( SearchScope.OBJECT, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        // (objectClass = *)
        ExprNode filter = searchRequest.getFilter();

        PresenceNode presenceNode = ( PresenceNode ) filter;
        assertNotNull( presenceNode );
        assertEquals( "objectClass", presenceNode.getAttribute() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 0, attributes.size() );

        // Check the encoding
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( new byte[]
            {
                0x30, 0x37,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x03,         // messageID MessageID
                  0x63, 0x32,               // CHOICE { ..., searchRequest SearchRequest, ...
                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x12,             // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                                            // baseObject (0),
                                            // singleLevel (1),
                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,       // derefAliases ENUMERATED {
                                            // neverDerefAliases (0),
                                            // derefInSearching (1),
                                            // derefFindingBaseObj (2),
                                            // derefAlways (3) },
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,       // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,       // typesOnly BOOLEAN, (FALSE)
                                            // filter Filter,
                                            // Filter ::= CHOICE {
                    ( byte ) 0x87, 0x0B,    // present [7] AttributeDescription,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                                            // attributes AttributeDescriptionList }
                    0x30, 0x00              // AttributeDescriptionList ::= SEQUENCE OF
                                            // AttributeDescription
            }, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with an empty attribute. The search
     * filter is : (objectclass=*)
     */
    @Test
    public void testDecodeSearchRequestOneEmptyAttribute()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x3F );
        stream.put( new byte[]
            {
                0x30, 0x3D,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x03,         // messageID MessageID
                  0x63, 0x38,               // CHOICE { ..., searchRequest SearchRequest, ...
                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x12,             // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                                            // baseObject (0),
                                            // singleLevel (1),
                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,       // derefAliases ENUMERATED {
                                            // neverDerefAliases (0),
                                            // derefInSearching (1),
                                            // derefFindingBaseObj (2),
                                            // derefAlways (3) },
                                            // sizeLimit INTEGER (0 .. maxInt), (infinite)
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,       // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,       // typesOnly BOOLEAN, (FALSE)
                                            // filter Filter,
                                            // Filter ::= CHOICE {
                    ( byte ) 0x87, 0x0B,    // present [7] AttributeDescription,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                                            // attributes AttributeDescriptionList }
                    0x30, 0x06,             // AttributeDescriptionList ::= SEQUENCE OF
                                            // AttributeDescription
                      0x04, 0x02,           // Request for sn
                        's', 'n',
                      0x04, 0x00            // Empty attribute
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 3, searchRequest.getMessageId() );
        assertEquals( "ou=users,ou=system", searchRequest.getBase().toString() );
        assertEquals( SearchScope.OBJECT, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        // (objectClass = *)
        ExprNode filter = searchRequest.getFilter();

        PresenceNode presenceNode = ( PresenceNode ) filter;
        assertNotNull( presenceNode );
        assertEquals( "objectClass", presenceNode.getAttribute() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 1, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( new byte[]
            {
                0x30, 0x3B,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x03,         // messageID MessageID
                  0x63, 0x36,               // CHOICE { ..., searchRequest SearchRequest, ...
                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x12,             // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                                            // baseObject (0),
                                            // singleLevel (1),
                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,       // derefAliases ENUMERATED {
                                            // neverDerefAliases (0),
                                            // derefInSearching (1),
                                            // derefFindingBaseObj (2),
                                            // derefAlways (3) },
                                            // sizeLimit INTEGER (0 .. maxInt), (infinite)
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,       // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,       // typesOnly BOOLEAN, (FALSE)
                                            // filter Filter,
                                            // Filter ::= CHOICE {
                    ( byte ) 0x87, 0x0B,    // present [7] AttributeDescription,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                                            // attributes AttributeDescriptionList }
                    0x30, 0x04,             // AttributeDescriptionList ::= SEQUENCE OF
                                            // AttributeDescription
                      0x04, 0x02,           // Request for sn
                        's', 'n',
            }, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a star and an attribute. The search
     * filter is : (objectclass=*)
     */
    @Test
    public void testDecodeSearchRequestWithStarAndAttr() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x40 );
        stream.put( new byte[]
            {
                0x30, 0x3E,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x03,         // messageID MessageID
                  0x63, 0x39,               // CHOICE { ..., searchRequest SearchRequest, ...
                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x12,             // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                                            // baseObject (0),
                                            // singleLevel (1),
                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,       // derefAliases ENUMERATED {
                                            // neverDerefAliases (0),
                                            // derefInSearching (1),
                                            // derefFindingBaseObj (2),
                                            // derefAlways (3) },
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,       // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,       // typesOnly BOOLEAN, (FALSE)
                                            // filter Filter,
                                            // Filter ::= CHOICE {
                    ( byte ) 0x87, 0x0B, // present [7] AttributeDescription,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                                            // attributes AttributeDescriptionList }
                    0x30, 0x07,             // AttributeDescriptionList ::= SEQUENCE OF
                                            // AttributeDescription
                      0x04, 0x02,           // Request for sn
                        's', 'n',
                      0x04, 0x01,
                        '*'                 // * attribute
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 3, searchRequest.getMessageId() );
        assertEquals( "ou=users,ou=system", searchRequest.getBase().toString() );
        assertEquals( SearchScope.OBJECT, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        // (objectClass = *)
        ExprNode filter = searchRequest.getFilter();

        PresenceNode presenceNode = ( PresenceNode ) filter;
        assertNotNull( presenceNode );
        assertEquals( "objectClass", presenceNode.getAttribute() );

        // The attributes
        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 2, attributes.size() );
        Set<String> expectedAttrs = new HashSet<String>();
        expectedAttrs.add( "sn" );
        expectedAttrs.add( "*" );

        for ( String attribute : attributes )
        {
            assertTrue( expectedAttrs.contains( attribute ) );
            expectedAttrs.remove( attribute );
        }

        assertEquals( 0, expectedAttrs.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Tests an search request decode with a simple equality match filter:
     * (|(uid=akarasulu)(cn=aok)(ou=Human Resources)(l=Santa Clara)(cn=abok))
     */
    @Test
    public void testDecodeSearchRequestOrFilters() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x96 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x93,
                  0x02, 0x01, 0x21,                 // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x8D,
                    0x04, 0x11,                     // "dc=example,dc=com"
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,               // scope ENUMERATED {
                    0x0A, 0x01, 0x02,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x02,               // sizeLimit INTEGER (0 .. maxInt), (2)
                    0x02, 0x01, 0x03,               // timeLimit INTEGER (0 .. maxInt), (3)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA1, 0x52,            // ( |
                      ( byte ) 0xA3, 0x10,          // ( uid=akarasulu )
                        0x04, 0x03,
                          'u', 'i', 'd',
                        0x04, 0x09,
                          'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u',
                      ( byte ) 0xA3, 0x09,          // ( cn=aok )
                        0x04, 0x02,
                          'c', 'n',
                        0x04, 0x03,
                          'a', 'o', 'k',
                      ( byte ) 0xA3, 0x15,          // ( ou=Human Resources )
                        0x04, 0x02,
                          'o', 'u',
                        0x04, 0x0F,
                          'H', 'u', 'm', 'a', 'n', ' ', 'R', 'e', 's', 'o', 'u', 'r', 'c', 'e', 's',
                      ( byte ) 0xA3, 0x10,
                        0x04, 0x01,
                          'l',                      // (l=Santa Clara )
                        0x04, 0x0B,
                          'S', 'a', 'n', 't', 'a', ' ', 'C', 'l', 'a', 'r', 'a',
                      ( byte ) 0xA3, 0x0A,          // ( cn=abok ))
                        0x04, 0x02,
                          'c', 'n',
                        0x04, 0x04,
                          'a', 'b', 'o', 'k',
                    0x30, 0x15,                     // Attributes
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',    // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 33, searchRequest.getMessageId() );
        assertEquals( "dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.OBJECT, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_FINDING_BASE_OBJ, searchRequest.getDerefAliases() );
        assertEquals( 2, searchRequest.getSizeLimit() );
        assertEquals( 3, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (objectclass=t*)
        OrNode orNode = ( OrNode ) searchRequest.getFilter();
        assertNotNull( orNode );
        assertEquals( 5, orNode.getChildren().size() );

        // uid=akarasulu
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) orNode.getChildren().get( 0 );

        assertEquals( "uid", equalityNode.getAttribute() );
        assertEquals( "akarasulu", equalityNode.getValue().getString() );

        // cn=aok
        equalityNode = ( EqualityNode<?> ) orNode.getChildren().get( 1 );

        assertEquals( "cn", equalityNode.getAttribute() );
        assertEquals( "aok", equalityNode.getValue().getString() );

        // ou = Human Resources
        equalityNode = ( EqualityNode<?> ) orNode.getChildren().get( 2 );

        assertEquals( "ou", equalityNode.getAttribute() );
        assertEquals( "Human Resources", equalityNode.getValue().getString() );

        // l=Santa Clara
        equalityNode = ( EqualityNode<?> ) orNode.getChildren().get( 3 );

        assertEquals( "l", equalityNode.getAttribute() );
        assertEquals( "Santa Clara", equalityNode.getValue().getString() );

        // cn=abok
        equalityNode = ( EqualityNode<?> ) orNode.getChildren().get( 4 );

        assertEquals( "cn", equalityNode.getAttribute() );
        assertEquals( "abok", equalityNode.getValue().getString() );

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
     * Test the decoding of a SearchRequest with controls.
     */
    @Test
    public void testDecodeSearchRequestWithControls() throws DecoderException, EncoderException
    {
        byte[] asn1BERJava5 = new byte[]
            {
                0x30, 0x7f,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x33,
                    0x04, 0x13,                     // baseObject: dc=my-domain,dc=com
                      'd', 'c', '=', 'm', 'y', '-', 'd', 'o', 'm', 'a', 'i', 'n', ',',
                      'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x02,               // scope ENUMERATED {
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,               // typesOnly BOOLEAN, (FALSE)
                    ( byte ) 0x87, 0x0b,            // Present filter: (objectClass=*)
                      'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                    0x30, 0x00,                     // Attributes = '*'
                    ( byte ) 0xa0, 0x45,            // controls
                      0x30, 0x28,
                        0x04, 0x16,                 // control
                          '1', '.', '2', '.', '8', '4', '0', '.',
                          '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '3', '1', '9',
                        0x01, 0x01, ( byte ) 0xff,  // criticality: false
                        0x04, 0x0b,
                          0x30, 0x09,
                            0x02, 0x01, 0x02,
                            0x04, 0x04,
                              0x47, 0x00, 0x00, 0x00, // value: pageSize=2
                      0x30, 0x19,
                        0x04, 0x17,                 // control
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                          '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2',
        };

        byte[] asn1BERJava6 = new byte[]
            {
                0x30, 0x7f,
                  0x02, 0x01, 0x04,                 // messageID
                  0x63, 0x33,
                    0x04, 0x13,                     // baseObject
                      'd', 'c', '=', 'm', 'y', '-', 'd', 'o', 'm', 'a', 'i', 'n', ',',
                      'd', 'c', '=', 'c', 'o', 'm',
                    0x0a, 0x01, 0x02,               // scope: subtree
                    0x0a, 0x01, 0x03,               // derefAliases: derefAlways
                    0x02, 0x01, 0x00,               // sizeLimit: 0
                    0x02, 0x01, 0x00,               // timeLimit: 0
                    0x01, 0x01, 0x00,               // typesOnly: false
                    ( byte ) 0x87, 0x0b,            // Present filter: (objectClass=*)
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                    0x30, 0x00,                     // Attributes = '*'
                    ( byte ) 0xa0, 0x45,            // controls
                      0x30, 0x19,
                        0x04, 0x17,                 // control
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                          '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2',
                      0x30, 0x28,
                        0x04, 0x16,                 // control
                          '1', '.', '2', '.', '8', '4', '0', '.',
                          '1', '1', '3', '5', '5', '6', '.', '1', '.', '4', '.', '3', '1', '9',
                        0x01, 0x01, ( byte ) 0xff, // criticality: false
                        0x04, 0x0b,
                          0x30, 0x09,
                            0x02, 0x01, 0x02,
                            0x04, 0x04,
                              0x47, 0x00, 0x00, 0x00, // value: pageSize=2
            };

        // For Java6
        ByteBuffer streamJava6 = ByteBuffer.allocate( asn1BERJava6.length );
        streamJava6.put( asn1BERJava6 );
        streamJava6.flip();

        // For Java5
        ByteBuffer streamJava5 = ByteBuffer.allocate( asn1BERJava5.length );
        streamJava5.put( asn1BERJava5 );

        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( streamJava6, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 4, searchRequest.getMessageId() );
        assertEquals( 2, searchRequest.getControls().size() );

        // this is a constant in Java 5 API
        String pagedResultsControlOID = "1.2.840.113556.1.4.319";
        Control pagedResultsControl = searchRequest.getControl( pagedResultsControlOID );
        assertEquals( pagedResultsControlOID, pagedResultsControl.getOid() );
        assertTrue( pagedResultsControl.isCritical() );

        // this is a constant in Java 5 API
        String manageReferralControlOID = "2.16.840.1.113730.3.4.2";
        Control manageReferralControl = searchRequest.getControl( manageReferralControlOID );
        assertEquals( manageReferralControlOID, manageReferralControl.getOid() );

        assertEquals( "dc=my-domain,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.SUBTREE, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        ExprNode filter = searchRequest.getFilter();

        assertTrue( filter instanceof PresenceNode );
        assertEquals( "objectClass", ( ( PresenceNode ) filter ).getAttribute() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( asn1BERJava6, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with no controls but with oid
     * attributes. The search filter is :
     * (&(|(objectclass=top)(2.5.4.11=contacts))(!(organizationalUnitName=ttt)))
     */
    @Test
    public void testDecodeSearchRequestGlobalNoControlsOidAndAlias()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0xA1 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x9E,         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                         // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x98,       // CHOICE { ...,
                                                            // searchRequest
                                                            // SearchRequest, ...
                                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                             // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                       // scope ENUMERATED {
                                                            // ENUMERATED
                                                            // {
                                                            // baseObject (0),
                                                            // singleLevel (1),
                                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                       // derefAliases ENUMERATED {
                                                            // neverDerefAliases (0),
                                                            // derefInSearching (1),
                                                            // derefFindingBaseObj (2),
                                                            // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,        // sizeLimit INTEGER (0 .. maxInt), (1000)

                    0x02, 0x02, 0x03, ( byte ) 0xE8,        // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,              // typesOnly BOOLEAN, (TRUE)
                                                            // filter Filter,
                    ( byte ) 0xA0, 0x4D,                    // Filter ::= CHOICE {
                                                            // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x2A,                  // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,                // equalityMatch [3]
                                                            // Assertion,
                                                            // Assertion ::= SEQUENCE {
                                                            // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                            // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x14,                // equalityMatch
                                                            // [3]
                                                            // Assertion,
                                                            // Assertion ::= SEQUENCE {
                          0x04, 0x08,
                            '2', '.', '5', '.', '4', '.', '1', '1', // attributeDesc
                                                            // AttributeDescription
                                                            // (LDAPString),
                                                            // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x1F,                  // not
                                                            // [2]
                                                            // Filter,
                        ( byte ) 0xA3, 0x1D,                // equalityMatch [3]
                                                            // Assertion,
                                                            // Assertion ::= SEQUENCE {
                                                            // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x16,
                            'o', 'r', 'g', 'a', 'n', 'i', 'z', 'a', 't', 'i', 'o', 'n', 'a', 'l',
                            'U', 'n', 'i', 't', 'N', 'a', 'm', 'e',
                          0x04, 0x03,                       // assertionValue AssertionValue (OCTET STRING) }
                            't', 't', 't',
                                                            // attributes AttributeDescriptionList }
                    0x30, 0x15,                             // AttributeDescriptionList ::= SEQUENCE OF
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',            // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (& (...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();

        // (& (| (...
        assertEquals( 2, andNodes.size() );
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        // (& (| (obectclass=top) (...
        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );

        EqualityNode<?> equalityNode = ( EqualityNode<?> ) orNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "top", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (...
        equalityNode = ( EqualityNode<?> ) orNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "2.5.4.11", equalityNode.getAttribute() );
        assertEquals( "contacts", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (! ...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (& (| (objectclass=top) (ou=contacts) ) (! (objectclass=ttt) ) )
        equalityNode = ( EqualityNode<?> ) notNode.getFirstChild();
        assertNotNull( equalityNode );

        assertEquals( "organizationalUnitName", equalityNode.getAttribute() );
        assertEquals( "ttt", equalityNode.getValue().getString() );

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
     * Test the decoding of a SearchRequest with SubEntry control.
     */
    @Test
    public void testDecodeSearchRequestSubEntryControl() throws DecoderException, EncoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x5D,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x33,
                    0x04, 0x13,                 // baseObject: dc=my-domain,dc=com
                      'd', 'c', '=', 'm', 'y', '-', 'd', 'o', 'm', 'a', 'i', 'n', ',',
                      'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x02,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,           // typesOnly BOOLEAN, (FALSE)
                    ( byte ) 0x87, 0x0b,        // filter: (objectClass=*)
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                    0x30, 0x00,
                      ( byte ) 0xa0, 0x23,      // controls
                    0x30, 0x21,
                      0x04, 0x17,
                        '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
                        '4', '2', '0', '3', '.', '1', '.', '1', '0', '.', '1', // SubEntry OID
                      0x01, 0x01, ( byte ) 0xFF, // criticality: true
                      0x04, 0x03,
                        0x01, 0x01, ( byte ) 0xFF // SubEntry visibility
        };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 4, searchRequest.getMessageId() );
        assertEquals( 1, searchRequest.getControls().size() );

        // SubEntry Control
        String subEntryControlOID = "1.3.6.1.4.1.4203.1.10.1";
        Control subEntryControl = searchRequest.getControl( subEntryControlOID );
        assertEquals( subEntryControlOID, subEntryControl.getOid() );
        assertTrue( subEntryControl.isCritical() );
        assertTrue( subEntryControl instanceof Subentries );
        assertTrue( ( ( Subentries ) subEntryControl ).isVisible() );

        assertEquals( "dc=my-domain,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.SUBTREE, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        ExprNode filter = searchRequest.getFilter();

        assertTrue( filter instanceof PresenceNode );
        assertEquals( "objectClass", ( ( PresenceNode ) filter ).getAttribute() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    // Defensive tests
    /**
     * Test the decoding of a SearchRequest with an empty body
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyBody() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x05,
                  0x02, 0x01, 0x04, // messageID MessageID
                  0x63, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty baseDN and nothing more
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestBaseDnOnly() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x07,
                  0x02, 0x01, 0x04, // messageID MessageID
                  0x63, 0x02,
                    0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with no controls. The search filter
     * is : (&(|(objectclass=top)(ou=contacts))(!(objectclass=ttt)))
     */
    @Test
    public void testDecodeSearchRequestEmptyBaseDnNoControls() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x6F );
        stream.put( new byte[]
            {
                0x30, 0x6D,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID
                  0x63, 0x68,                       // CHOICE { ...,
                                                    // searchRequest SearchRequest, ...
                                                    // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x00,                     // baseObject LDAPDN,
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte )0xE8, // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte )0xE8, // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE)
                                                    // filter Filter,
                    ( byte ) 0xA0, 0x3C,            // Filter ::= CHOICE {
                                                    // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,          // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,        // equalityMatch [3]
                                                    // Assertion,
                                                    // Assertion ::= SEQUENCE {
                                                    // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                    // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,        // equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',               // attributeDesc AttributeDescription (LDAPString),
                                                    // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,          // not [2] Filter,
                        ( byte ) 0xA3, 0x12,        // equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                                                    // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                    // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 't', 't',
                                                    // attributes AttributeDescriptionList }
                    0x30, 0x15,                     // AttributeDescriptionList ::= SEQUENCE OF
                                                    // AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',    // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a SearchRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 1000, searchRequest.getSizeLimit() );
        assertEquals( 1000, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (& (...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();

        // (& (| (...
        assertEquals( 2, andNodes.size() );
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        // (& (| (obectclass=top) (...
        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );

        EqualityNode<?> equalityNode = ( EqualityNode<?> ) orNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "top", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (...
        equalityNode = ( EqualityNode<?> ) orNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "ou", equalityNode.getAttribute() );
        assertEquals( "contacts", equalityNode.getValue().getString() );

        // (& (| (objectclass=top) (ou=contacts) ) (! ...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (& (| (objectclass=top) (ou=contacts) ) (! (objectclass=ttt) ) )
        equalityNode = ( EqualityNode<?> ) notNode.getFirstChild();
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "ttt", equalityNode.getValue().getString() );

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
     * Test the decoding of a SearchRequest with a bad objectBase
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestGlobalBadObjectBase() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x90 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8D,         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                         // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x87,       // CHOICE { ...,
                                                            // searchRequest SearchRequest, ...
                                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                             // baseObject LDAPDN,
                      'u', 'i', 'd', ':', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,                       // scope ENUMERATED {
                                                            // baseObject (0),
                                                            // singleLevel (1),
                                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                       // derefAliases ENUMERATED {
                                                            // neverDerefAliases (0),
                                                            // derefInSearching (1),
                                                            // derefFindingBaseObj (2),
                                                            // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte )0xE8,         // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte )0xE8,         // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,              // typesOnly BOOLEAN, (TRUE)
                                                            // filter Filter,
                    ( byte ) 0xA0, 0x3C,                    // Filter ::= CHOICE {
                                                            // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,                  // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,                // equalityMatch [3]
                                                            // Assertion,
                                                            // Assertion ::= SEQUENCE {
                                                            // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                            // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,                // equalityMatch [3] Assertion,
                                                            // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',                       // attributeDesc AttributeDescription (LDAPString),
                                                            // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,                  // not [2] Filter,
                        ( byte ) 0xA3, 0x12,                // equalityMatch [3] Assertion,
                                                            // Assertion ::= SEQUENCE {
                                                            // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                            // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 't', 't',
                                                            // attributes AttributeDescriptionList }
                    0x30, 0x15,                             // AttributeDescriptionList ::= SEQUENCE OF
                                                            // AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',            // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        try
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof SearchResultDoneImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( SearchResultDoneImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of a SearchRequest with an empty scope
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyScope() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x28,
                  0x02, 0x01, 0x04,     // messageID MessageID
                  0x63, 0x23,
                    0x04, 0x1F,         // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a bad scope
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestGlobalBadScope() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x90 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8D,         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                         // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x87,       // CHOICE { ...,
                                                            // searchRequest SearchRequest, ...
                                                            // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                             // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x03,                       // scope ENUMERATED {
                                                            // baseObject (0),
                                                            // singleLevel (1),
                                                            // wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                       // derefAliases ENUMERATED {
                                                            // neverDerefAliases (0),
                                                            // derefInSearching (1),
                                                            // derefFindingBaseObj (2),
                                                            // derefAlways (3) },
                0x02, 0x02, 0x03, ( byte )0xE8,             // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte )0xE8,         // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,              // typesOnly BOOLEAN, (TRUE)
                                                            // filter Filter,
                    ( byte ) 0xA0, 0x3C,                    // Filter ::= CHOICE {
                                                            // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,                  // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,                // equalityMatch [3]
                                                            // Assertion,
                                                            // Assertion ::= SEQUENCE {
                                                            // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,                       // assertionValue AssertionValue (OCTET STRING) }
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,                // equalityMatch [3] Assertion,
                                                            // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',                       // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x08,                       // assertionValue AssertionValue (OCTET STRING) }
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,                  // not [2] Filter,
                        ( byte ) 0xA3, 0x12,                // equalityMatch [3] Assertion,
                                                            // Assertion ::= SEQUENCE {
                          0x04, 0x0B,                       // attributeDesc AttributeDescription (LDAPString),
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,                       // assertionValue AssertionValue (OCTET STRING) }
                            't', 't', 't',
                                                            // attributes AttributeDescriptionList }
                    0x30, 0x15,                             // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',            // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',            // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty derefAlias
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyDerefAlias() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x2B,
                  0x02, 0x01, 0x04,         // messageID MessageID
                  0x63, 0x26,
                    0x04, 0x1F,             // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                    0x0A, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a bad derefAlias
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestGlobalBadDerefAlias() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x90 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8D, // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x87, // CHOICE { ...,
                                                    // searchRequest SearchRequest, ...
                                                    // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x1F,                     // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    // baseObject (0),
                                                    // singleLevel (1),
                                                    // wholeSubtree (2) },
                    0x0A, 0x01, 0x04,               // derefAliases ENUMERATED {
                                                    // neverDerefAliases (0),
                                                    // derefInSearching (1),
                                                    // derefFindingBaseObj (2),
                                                    // derefAlways (3) },
                    0x02, 0x02, 0x03, ( byte ) 0xE8,// sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte ) 0xE8,// timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE)
                                                    // filter Filter,
                    ( byte ) 0xA0, 0x3C,            // Filter ::= CHOICE {
                                                    // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,          // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,        // equalityMatch [3]
                                                    // Assertion,
                                                    // Assertion ::= SEQUENCE {
                                                    // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,               // assertionValue AssertionValue (OCTET STRING) }
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,        // equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',               // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x08,               // assertionValue AssertionValue (OCTET STRING) }
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,          // not [2] Filter,
                        ( byte ) 0xA3, 0x12,        // equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                          0x04, 0x0B,               // attributeDesc AttributeDescription (LDAPString),
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,               // assertionValue AssertionValue (OCTET STRING) }
                            't', 't', 't',
                                                    // attributes AttributeDescriptionList }
                    0x30, 0x15,                     // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',    // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',    // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty size limit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptySizeLimit() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x2E,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x29,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a bad sizeLimit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestGlobalBadSizeLimit() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x8F );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8C,     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x86,   // CHOICE { ...,
                                                        // searchRequest SearchRequest, ...
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
                    0x02, 0x01, ( byte )0xFF,           // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x02, 0x03, ( byte )0xE8,     // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE)
                                                        // filter Filter,
                    ( byte ) 0xA0, 0x3C,                // Filter ::= CHOICE {
                                                        // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,              // or [1] SET of Filter,
                        ( byte ) 0xA3, 0x12,            // equalityMatch [3]
                                                        // Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x0B,                   // attributeDesc AttributeDescription (LDAPString),
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,                   // assertionValue AssertionValue (OCTET STRING) }
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,            // equalityMatch [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x02,
                            'o', 'u',                   // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x08,                   // assertionValue AssertionValue (OCTET STRING) }
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,              // not [2] Filter,
                        ( byte ) 0xA3, 0x12,            // equalityMatch [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x0B,                   // attributeDesc AttributeDescription (LDAPString),
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                          0x04, 0x03,                   // assertionValue AssertionValue (OCTET STRING) }
                            't', 't', 't',
                                                        // attributes AttributeDescriptionList }
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF
                      0x04, 0x05,                       // AttributeDescription
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',        // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty time limit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyTimeLimit() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x31,
                  0x02, 0x01, 0x04,         // messageID MessageID
                  0x63, 0x2C,
                    0x04, 0x1F,             // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,       // scope ENUMERATED {
                    0x0A, 0x01, 0x00,       // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,       // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a bad timeLimit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestGlobalBadTimeLimit() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x8F );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x81, ( byte ) 0x8C,     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID MessageID
                  0x63, ( byte ) 0x81, ( byte ) 0x86,   // CHOICE { ...,
                                                        // searchRequest SearchRequest, ...
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
                    0x02, 0x02, 0x03, ( byte )0xE8,     // sizeLimit INTEGER (0 .. maxInt), (1000)
                    0x02, 0x01, ( byte )0xFF,           // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE)
                                                        // filter Filter,
                    ( byte ) 0xA0, 0x3C,                // Filter ::= CHOICE {
                                                        // and [0] SET OF Filter,
                      ( byte ) 0xA1, 0x24,              // or [1] SET of Filter,
                    ( byte ) 0xA3, 0x12,                // equalityMatch [3]
                                                        // Assertion,
                                                        // Assertion ::= SEQUENCE {
                                                        // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                            't', 'o', 'p',
                        ( byte ) 0xA3, 0x0E,            // equalityMatch [3] Assertion,
                          0x04, 0x02,
                            'o', 'u',                   // attributeDesc AttributeDescription (LDAPString),
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x08,
                            'c', 'o', 'n', 't', 'a', 'c', 't', 's',
                      ( byte ) 0xA2, 0x14,              // not [2] Filter,
                        ( byte ) 0xA3, 0x12,            // equalityMatch [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                                                        // attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                                                        // assertionValue AssertionValue (OCTET STRING) }
                          0x04, 0x03,
                           't', 't', 't',
                                                        // attributes AttributeDescriptionList }
                    0x30, 0x15,                         // AttributeDescriptionList ::= SEQUENCE OF
                                                        // AttributeDescription
                      0x04, 0x05,
                        'a', 't', 't', 'r', '0',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '1',        // AttributeDescription ::= LDAPString
                      0x04, 0x05,
                        'a', 't', 't', 'r', '2',        // AttributeDescription ::= LDAPString
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyTypeOnly() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x34,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x2F,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA0, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty Present filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyPresentFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0x87, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty equalityMatch filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyEqualityMatchFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA3, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty greaterOrEqual filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyGreaterOrEqualFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA5, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty lessOrEqual filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyLessOrEqualFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
              0x02, 0x01, 0x04,                 // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA6, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an approxMatch filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyApproxMatchFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x37,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x32,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA8, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a greaterOrEqual filter and an
     * empty attributeDesc
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyGreaterOrEqualEmptyAttrDesc()
        throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x39,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x34,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED {
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA5, 0x02,
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a greaterOrEqual filter and an
     * empty attributeValue, and an empty attribute List
     */
    @Test
    public void testDecodeSearchRequestEmptyGreaterOrEqualEmptyAttrValue()
        throws DecoderException, EncoderException, LdapException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x41,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x3C,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA5, 0x08,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x04, 0x00,
                    0x30, 0x00                  // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
        };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 4, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // >=
        GreaterEqNode<?> greaterOrEqual = ( GreaterEqNode<?> ) searchRequest.getFilter();

        assertNotNull( greaterOrEqual );

        assertEquals( "test", greaterOrEqual.getAttribute() );
        assertEquals( "", greaterOrEqual.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a greaterOrEqual filter and an
     * empty attributeValue, and an '*' attribute List
     */
    @Test
    public void testDecodeSearchRequestEmptyGreaterOrEqualEmptyAttrValueStar()
        throws DecoderException, EncoderException, LdapException
    {
        byte[] asn1BER = new byte[]
            {
              0x30, 0x44,
                0x02, 0x01, 0x04, // messageID MessageID
                0x63, 0x3F,
                  0x04, 0x1F, // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                  0x0A, 0x01, 0x01, // scope ENUMERATED {
                  0x0A, 0x01, 0x03, // derefAliases ENUMERATED {
                  0x02, 0x01, 0x00, // sizeLimit INTEGER (0 .. maxInt), (0)
                  0x02, 0x01, 0x00, // timeLimit INTEGER (0 .. maxInt), (0)
                  0x01, 0x01, ( byte ) 0xFF,// typesOnly BOOLEAN, (TRUE)
                  ( byte ) 0xA5, 0x08,
                    0x04, 0x04,
                      't', 'e', 's', 't',
                    0x04, 0x00,
                  0x30, 0x03,             // AttributeDescriptionList ::= SEQUENCE
                                          // OF AttributeDescription
                    0x04, 0x01, '*'
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 4, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // >=
        GreaterEqNode<?> greaterOrEqual = ( GreaterEqNode<?> ) searchRequest.getFilter();

        assertNotNull( greaterOrEqual );

        assertEquals( "test", greaterOrEqual.getAttribute() );
        assertEquals( "", greaterOrEqual.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 1, attributes.size() );
        assertEquals( "*", attributes.get( 0 ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest with a greaterOrEqual filter and an
     * empty attributeValue, and an empty attribute List
     */
    @Test
    public void testDecodeSearchRequestEmptyGreaterOrEqualEmptyAttrValueEmpty() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x43,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x3E,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA5, 0x08,
                      0x04, 0x04,
                        't', 'e', 's', 't',
                      0x04, 0x00,
                    0x30, 0x02,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                    0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 4, searchRequest.getMessageId() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // >=
        GreaterEqNode<?> greaterOrEqual = ( GreaterEqNode<?> ) searchRequest.getFilter();

        assertNotNull( greaterOrEqual );

        assertEquals( "test", greaterOrEqual.getAttribute() );
        assertEquals( "", greaterOrEqual.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();

        assertEquals( 0, attributes.size() );
    }


    /**
     * Test the decoding of a SearchRequest with an empty And filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyAndFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3B,
                  0x02, 0x01, 0x04, // messageID MessageID
                  0x63, 0x36,
                    0x04, 0x1F, // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01, // scope ENUMERATED {
                    0x0A, 0x01, 0x03, // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00, // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00, // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,// typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA0, 0x00,
                    0x30, 0x02,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty Or filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyOrFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3B,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x36,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA1, 0x00,
                    0x30, 0x02,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with an empty Not filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestEmptyNotFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3B,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x36,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA2, 0x00,
                    0x30, 0x02,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
                      0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a Not filter and an empty And
     * filter
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchRequestNotFilterEmptyAndFilter() throws DecoderException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x3D,
                  0x02, 0x01, 0x04,             // messageID MessageID
                  0x63, 0x38,
                    0x04, 0x1F,                 // baseObject LDAPDN,
                    'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xA2, 0x02,
                      ( byte ) 0xA0, 0x00,
                0x30, 0x02,                     // AttributeDescriptionList ::= SEQUENCE OF
                                                // AttributeDescription
                  0x04, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchRequest with a greaterOrEqual filter and an
     * empty attributeValue, and an '*' attribute List
     */
    @Test
    public void testDecodeSearchRequestDIRSERVER_651() throws DecoderException, EncoderException, LdapException
    {
        byte[] asn1BER = new byte[]
            {
                0x30, 0x60,
                  0x02, 0x01, 0x02,                 // messageID MessageID
                  0x63, 0x5b,
                    0x04, 0x0a,
                      'd', 'c', '=', 'p', 'g', 'p', 'k', 'e', 'y', 's',
                    0x0A, 0x01, 0x02,               // scope ENUMERATED {
                    0x0A, 0x01, 0x00,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,               // typesOnly BOOLEAN, (FALSE)
                    ( byte ) 0xa0, 0x3c,
                      ( byte ) 0xa4, 0x28,
                        0x04, 0x09,
                          'p', 'g', 'p', 'u', 's', 'e', 'r', 'i', 'd',
                        0x30, 0x1b,
                          ( byte ) 0x80, 0x19,
                            'v', 'g', 'j', 'o', 'k', 'j', 'e', 'v', '@', 'n', 'e', 't', 'c', 'e', 't', 'e',
                            'r', 'a', '.', 'c', 'o', 'm', '.', 'm', 'k',
                      ( byte ) 0xa3, 0x10,
                        0x04, 0x0b,
                          'p', 'g', 'p', 'd', 'i', 's', 'a', 'b', 'l', 'e', 'd',
                        0x04, 0x01,
                          '0',
                    0x30, 0x00
            };

        ByteBuffer stream = ByteBuffer.allocate( asn1BER.length );
        stream.put( asn1BER );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        // Decode a SearchRequest message
        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 2, searchRequest.getMessageId() );
        assertEquals( "dc=pgpkeys", searchRequest.getBase().toString() );
        assertEquals( SearchScope.SUBTREE, searchRequest.getScope() );
        assertEquals( AliasDerefMode.NEVER_DEREF_ALIASES, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        // And
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        SubstringNode substringNode = ( SubstringNode ) andNodes.get( 0 );
        assertNotNull( substringNode );

        assertEquals( "pgpuserid", substringNode.getAttribute() );
        assertEquals( "vgjokjev@netcetera.com.mk", substringNode.getInitial() );
        assertEquals( 0, substringNode.getAny().size() );
        assertEquals( null, substringNode.getFinal() );

        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "pgpdisabled", equalityNode.getAttribute() );
        assertEquals( "0", equalityNode.getValue().getString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (a=b)
     */
    @Test
    public void testDecodeSearchRequestEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x25 );
        stream.put( new byte[]
            {
                0x30, 0x23,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x1E,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA3, 0x06,        // Filter ::= CHOICE {
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                      0x04, 0x01,
                        'a',                    //      attributeDesc AttributeDescription (LDAPString),
                      0x04, 0x01,
                        'b',                    //      assertionValue AssertionValue (OCTET STRING) }
                                                // attributes AttributeDescriptionList }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (a=b)
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) searchRequest.getFilter();

        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(a=b))
     */
    @Test
    public void testDecodeSearchRequestAndEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x27 );
        stream.put( new byte[]
            {
                0x30, 0x25,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x20,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x08,        // Filter ::= CHOICE {
                      ( byte ) 0xA3, 0x06,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'a',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'b',                  //      assertionValue AssertionValue (OCTET STRING) }
                                                // attributes AttributeDescriptionList }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 1, andNodes.size() );

        // (&(a=b))
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(a=b)(c=d))
     */
    @Test
    public void testDecodeSearchRequestAndEqEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x2F );
        stream.put( new byte[]
            {
                0x30, 0x2D,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x28,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x10,        // Filter ::= CHOICE {
                      ( byte ) 0xA3, 0x06,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'a',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'b',                  //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA3, 0x06,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'c',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'd',                  //      assertionValue AssertionValue (OCTET STRING) }
                                                // attributes AttributeDescriptionList }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(a=b)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(a=b)(c=d))
        equalityNode = ( EqualityNode<?> ) andNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b))
     */
    @Test
    public void testDecodeSearchRequestAndAndEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x29 );
        stream.put( new byte[]
            {
                0x30, 0x27,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x22,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (1000)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x0A,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x08,      // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 1, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(&(a=b)))
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b)(c=d))
     */
    @Test
    public void testDecodeSearchRequestAndAndEqEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x31 );
        stream.put( new byte[]
            {
                0x30, 0x2F,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x2A,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x12,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x10,      // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                //      assertionValue AssertionValue (OCTET STRING) }
                        ( byte ) 0xA3, 0x06,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'c',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'd',                //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 1, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 2, andNodes2.size() );

        // (&(&(a=b)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(&(a=b)(c=d)
        equalityNode = ( EqualityNode<?> ) andNodes2.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b))(c=d))
     * @throws LdapException
     */
    @Test
    public void testDecodeSearchRequestAnd_AndEq_Eq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x31 );
        stream.put( new byte[]
            {
                0x30, 0x2F,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x2A,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                    'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x12,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x08,      // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA3, 0x06,      //      equalityMatch [3] Assertion,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'c',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'd',                  //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(&(a=b))...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(&(a=b))(c=d))
        equalityNode = ( EqualityNode<?> ) andNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b)(c=d))(e=f))
     */
    @Test
    public void testDecodeSearchRequestAnd_AndEqEq_Eq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x39 );
        stream.put( new byte[]
            {
                0x30, 0x37,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x32,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x1A,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x10,      // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                //      assertionValue AssertionValue (OCTET STRING) }
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'c',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'd',                //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA3, 0x06,      //      equalityMatch [3] Assertion,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'e',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'f',                  //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 2, andNodes2.size() );

        // (&(&(a=b)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(&(a=b)(c=d)...
        equalityNode = ( EqualityNode<?> ) andNodes2.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        // (&(&(a=b)(c=d))(e=f))
        equalityNode = ( EqualityNode<?> ) andNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "e", equalityNode.getAttribute() );
        assertEquals( "f", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(a=b)(|(a=b)(c=d)))
     */
    @Test
    public void testDecodeSearchRequestAndEq_OrEqEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x39 );
        stream.put( new byte[]
            {
                0x30, 0x37,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x32,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x1A,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA3, 0x06,      //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'a',                  //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'b',                  //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA1, 0x10,      // Filter ::= CHOICE { or             [1] SET OF Filter,
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'c',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'd',                //      assertionValue AssertionValue (OCTET STRING) }
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'e',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'f',                //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00,                 // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode exprNode = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) exprNode;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(a=b)..
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(a=b)(|(...
        OrNode orNode = ( OrNode ) andNodes.get( 1 );
        assertNotNull( orNode );

        List<ExprNode> orNodes = orNode.getChildren();
        assertEquals( 2, orNodes.size() );

        // (&(a=b)(|(c=d)...
        equalityNode = ( EqualityNode<?> ) orNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        // (&(a=b)(|(c=d)(e=f)))
        equalityNode = ( EqualityNode<?> ) orNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "e", equalityNode.getAttribute() );
        assertEquals( "f", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b))(&(c=d)))
     */
    @Test
    public void testDecodeSearchRequestAnd_AndEq_AndEq()
        throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x33 );
        stream.put( new byte[]
            {
                0x30, 0x31,                     // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x2C,                   // CHOICE { ...,
                                                // searchRequest SearchRequest, ...
                                                // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                 // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,           // scope ENUMERATED {
                                                //      baseObject (0),
                                                //      singleLevel (1),
                                                //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,           // derefAliases ENUMERATED {
                                                //      neverDerefAliases (0),
                                                //      derefInSearching (1),
                                                //      derefFindingBaseObj (2),
                                                //      derefAlways (3) },
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,           // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,  // typesOnly BOOLEAN, (TRUE)
                                                // filter Filter,
                    ( byte ) 0xA0, 0x14,        // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x08,      // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,    //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                //      assertionValue AssertionValue (OCTET STRING) }
                        ( byte ) 0xA0, 0x08,    // Filter ::= CHOICE { and             [0] SET OF Filter,
                          ( byte ) 0xA3, 0x06,  //      equalityMatch [3] Assertion,
                                                //      equalityMatch [3] Assertion,
                                                // Assertion ::= SEQUENCE {
                              0x04, 0x01,
                                'c',            //      attributeDesc AttributeDescription (LDAPString),
                              0x04, 0x01,
                                'd',            //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00                  // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(&(a=b)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(&(a=b))(&...
        andNode2 = ( AndNode ) andNodes.get( 1 );
        assertNotNull( andNode2 );

        andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(&(a=b))(&(c=d)))
        equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(&(a=b)(c=d))(&(e=f)))
     */
    @Test
    public void testDecodeSearchRequestAnd_AndEqEq_AndEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x3B );
        stream.put( new byte[]
            {
                0x30, 0x39,                         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                 // messageID MessageID
                  0x63, 0x34,                       // CHOICE { ...,
                                                    // searchRequest SearchRequest, ...
                                                    // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                     // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                                                    //      baseObject (0),
                                                    //      singleLevel (1),
                                                    //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                                                    //      neverDerefAliases (0),
                                                    //      derefInSearching (1),
                                                    //      derefFindingBaseObj (2),
                                                    //      derefAlways (3) },
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE)
                                                    // filter Filter,
                    ( byte ) 0xA0, 0x1C,            // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA0, 0x10,          // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,        //      equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'a',                    //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'b',                    //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA3, 0x06,          //      equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                        0x04, 0x01,
                          'c',                      //      attributeDesc AttributeDescription (LDAPString),
                        0x04, 0x01,
                          'd',                      //      assertionValue AssertionValue (OCTET STRING) }
                      ( byte ) 0xA0, 0x08,          // Filter ::= CHOICE { and             [0] SET OF Filter,
                        ( byte ) 0xA3, 0x06,        //      equalityMatch [3] Assertion,
                                                    //      equalityMatch [3] Assertion,
                                                    // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'e',                    //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'f',                    //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00                      // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(&(..
        AndNode andNode2 = ( AndNode ) andNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 2, andNodes2.size() );

        // (&(&(a=b)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "a", equalityNode.getAttribute() );
        assertEquals( "b", equalityNode.getValue().getString() );

        // (&(&(a=b)(c=d))...
        equalityNode = ( EqualityNode<?> ) andNodes2.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "c", equalityNode.getAttribute() );
        assertEquals( "d", equalityNode.getValue().getString() );

        // (&(&(a=b)(c=d))(&...
        andNode2 = ( AndNode ) andNodes.get( 1 );
        assertNotNull( andNode2 );

        andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(&(a=b)(c=d))(&(e=f)))
        equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "e", equalityNode.getAttribute() );
        assertEquals( "f", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * (&(|(abcdef=*)(ghijkl=*))(!(e>=f)))
     */
    @Test
    public void testDecodeSearchRequestAnd_OrPrPr_NotGEq() throws DecoderException, EncoderException, LdapException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x3B );
        stream.put( new byte[]
            {
                0x30, 0x39,                             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,                     // messageID MessageID
                  0x63, 0x34,                           // CHOICE { ...,
                                                        // searchRequest SearchRequest, ...
                                                        // SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x03,                         // baseObject LDAPDN,
                      'a', '=', 'b',
                    0x0A, 0x01, 0x01,                   // scope ENUMERATED {
                                                        //      baseObject (0),
                                                        //      singleLevel (1),
                                                        //      wholeSubtree (2) },
                    0x0A, 0x01, 0x03,                   // derefAliases ENUMERATED {
                                                        //      neverDerefAliases (0),
                                                        //      derefInSearching (1),
                                                        //      derefFindingBaseObj (2),
                                                        //      derefAlways (3) },
                    0x02, 0x01, 0x00,                   // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,                   // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,          // typesOnly BOOLEAN, (TRUE)
                                                        // filter Filter,
                    ( byte ) 0xA0, 0x1C,                // Filter ::= CHOICE { and             [0] SET OF Filter,
                      ( byte ) 0xA1, 0x10,              // Filter ::= CHOICE { or             [0] SET OF Filter,
                        ( byte ) 0x87, 0x06,            // present [7] AttributeDescription,
                         'a', 'b', 'c', 'd', 'e', 'f',  // AttributeDescription ::= LDAPString
                        ( byte ) 0x87, 0x06,            // present [7] AttributeDescription,
                          'g', 'h', 'i', 'j', 'k', 'l', // AttributeDescription ::= LDAPString
                      ( byte ) 0xA2, 0x08,              // Filter ::= CHOICE { not             Filter,
                        ( byte ) 0xA5, 0x06,            //      greaterOrEqual [3] Assertion,
                                                        // Assertion ::= SEQUENCE {
                          0x04, 0x01,
                            'e',                        //      attributeDesc AttributeDescription (LDAPString),
                          0x04, 0x01,
                            'f',                        //      assertionValue AssertionValue (OCTET STRING) }
                    0x30, 0x00                          // AttributeDescriptionList ::= SEQUENCE OF AttributeDescription
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "a=b", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(|(..
        OrNode orFilter = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orFilter );

        List<ExprNode> orNodes = orFilter.getChildren();
        assertEquals( 2, orNodes.size() );

        // (&(&(abcdef=*)...
        PresenceNode presenceNode = ( PresenceNode ) orNodes.get( 0 );
        assertNotNull( presenceNode );

        assertEquals( "abcdef", presenceNode.getAttribute() );

        // (&(&(abcdef=*)(ghijkl=*))...
        presenceNode = ( PresenceNode ) orNodes.get( 1 );
        assertNotNull( presenceNode );

        assertEquals( "ghijkl", presenceNode.getAttribute() );

        // (&(&(abcdef=*)(ghijkl=*))(&...
        NotNode notNode = ( NotNode ) andNodes.get( 1 );
        assertNotNull( notNode );

        // (&(&(abcdef=*)(ghijkl=*))(&(e>=f)))
        GreaterEqNode<?> greaterEqNode = ( GreaterEqNode<?> ) notNode.getFirstChild();
        assertNotNull( greaterEqNode );

        assertEquals( "e", greaterEqNode.getAttribute() );
        assertEquals( "f", greaterEqNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, searchRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchRequest
     * for rootDSE
     */
    @Test
    public void testDecodeSearchRequestRootDse() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x33 );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x2D,
                  0x02, 0x01, 0x01,                 // messageID MessageID
                  0x63, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x24,
                    0x04, 0x00,
                    0x0A, 0x01, 0x00,               // scope ENUMERATED {
                    0x0A, 0x01, 0x00,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,
                    ( byte ) 0x87, 0x0B,
                      'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                    0x30, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, searchRequest.getMessageId() );
        assertEquals( "", searchRequest.getBase().toString() );
        assertEquals( SearchScope.OBJECT, searchRequest.getScope() );
        assertEquals( AliasDerefMode.NEVER_DEREF_ALIASES, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        ExprNode filter = searchRequest.getFilter();

        PresenceNode presenceNode = ( PresenceNode ) filter;
        assertNotNull( presenceNode );
        assertEquals( "objectClass", presenceNode.getAttribute() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );
    }


    /**
     * Test the decoding of a SearchRequest with special length (long form)
     * for rootDSE
     */
    @Test
    public void testDecodeSearchRequestDIRSERVER_810() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x6B );
        stream.put( new byte[]
            {
                0x30, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x65,
                  0x02, 0x01, 0x03,                 // messageID MessageID
                  0x63, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x5c,
                    0x04, 0x12,                     // 'ou=users,ou=system'
                      'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x01,               // scope ENUMERATED {
                    0x0A, 0x01, 0x00,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x1E,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, ( byte ) 0xFF,      // typesOnly BOOLEAN, (TRUE)
                    ( byte ) 0xa0, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x2d,
                      ( byte ) 0xa3, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x0e,
                        0x04, 0x03,
                          'u', 'i', 'd',
                        0x04, 0x07,
                          'b', 'u', 's', 't', 'e', 'r', ' ', // 'buster ' (with a space at the end)
                      ( byte ) 0xa3, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x13,
                        0x04, 0x0b,
                          's', 'b', 'A', 't', 't', 'r', 'i', 'b', 'u', 't', 'e', // sbAttribute
                        0x04, 0x04,
                            'B', 'u', 'y', ' ',     // 'Buy ' (with a space at the end)
                    0x30, ( byte ) 0x84, 0x00, 0x00, 0x00, 0x00
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 3, searchRequest.getMessageId() );
        assertEquals( "ou=users,ou=system", searchRequest.getBase().toString() );
        assertEquals( SearchScope.ONELEVEL, searchRequest.getScope() );
        assertEquals( AliasDerefMode.NEVER_DEREF_ALIASES, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 30, searchRequest.getTimeLimit() );
        assertEquals( true, searchRequest.getTypesOnly() );

        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(uid=buster)...
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "uid", equalityNode.getAttribute() );
        assertEquals( "buster ", equalityNode.getValue().getString() );

        // (&(uid=buster)(sbAttribute=Buy))
        equalityNode = ( EqualityNode<?> ) andNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "sbAttribute", equalityNode.getAttribute() );
        assertEquals( "Buy ", equalityNode.getValue().getString() );

        List<String> attributes = searchRequest.getAttributes();
        assertEquals( 0, attributes.size() );
    }


    /**
     * Test the decoding of a SearchRequest with a complex filter :
     * (&(objectClass=person)(|(cn=Tori*)(sn=Jagger)))
     */
    @Test
    public void testDecodeSearchRequestComplexFilterWithControl() throws DecoderException
    {

        ByteBuffer stream = ByteBuffer.allocate( 0x77 );
        stream.put( new byte[]
            {
                0x30, 0x75,                         // LdapMessage
                  0x02, 0x01, 0x06,                 // messageID MessageID
                  0x63, 0x53,                       // SearchRequest
                    0x04, 0x09,                     // BaseDN 'ou=system'
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x02,               // scope ENUMERATED {
                    0x0A, 0x01, 0x03,               // derefAliases ENUMERATED {
                    0x02, 0x01, 0x00,               // sizeLimit INTEGER (0 .. maxInt), (0)
                    0x02, 0x01, 0x00,               // timeLimit INTEGER (0 .. maxInt), (0)
                    0x01, 0x01, 0x00,               // typesOnly BOOLEAN, (FALSE)
                    ( byte ) 0xA0, 0x35,            // AND
                        ( byte ) 0xA3, 0x15,        // equals
                          0x04, 0x0B,
                            'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
                          0x04, 0x06,               // 'person'
                            'p', 'e', 'r', 's', 'o', 'n',
                        ( byte ) 0xA1, 0x1C,        // OR
                          ( byte ) 0xA4, 0x0C,      // substrings : 'cn=Tori*'
                            0x04, 0x02,             // 'cn'
                              'c', 'n',
                            0x30, 0x06,             // initial = 'Tori'
                              ( byte ) 0x80, 0x04,
                                'T', 'o', 'r', 'i',
                          ( byte ) 0xA3, 0x0C,      // equals
                            0x04, 0x02,             // 'sn'
                              's', 'n',
                            0x04, 0x06,             // 'Jagger'
                              'J', 'a', 'g', 'g', 'e', 'r',
                    0x30, 0x00,
                    ( byte ) 0xA0, 0x1B,            // Control
                      0x30, 0x19,
                        0x04, 0x17,
                          '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                          '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer =
            new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 6, searchRequest.getMessageId() );
        assertEquals( "ou=system", searchRequest.getBase().toString() );
        assertEquals( SearchScope.SUBTREE, searchRequest.getScope() );
        assertEquals( AliasDerefMode.DEREF_ALWAYS, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        // (&(...
        ExprNode filter = searchRequest.getFilter();

        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(objectClass=person)..
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "objectClass", equalityNode.getAttribute() );
        assertEquals( "person", equalityNode.getValue().getString() );

        // (&(a=b)(|
        OrNode orNode = ( OrNode ) andNodes.get( 1 );
        assertNotNull( orNode );

        List<ExprNode> orNodes = orNode.getChildren();
        assertEquals( 2, orNodes.size() );

        // (&(a=b)(|(cn=Tori*
        SubstringNode substringNode = ( SubstringNode ) orNodes.get( 0 );
        assertNotNull( substringNode );

        assertEquals( "cn", substringNode.getAttribute() );
        assertEquals( "Tori", substringNode.getInitial() );
        assertEquals( 0, substringNode.getAny().size() );
        assertEquals( null, substringNode.getFinal() );

        // (&(a=b)(|(cn=Tori*)(sn=Jagger)))
        equalityNode = ( EqualityNode<?> ) orNodes.get( 1 );
        assertNotNull( equalityNode );

        assertEquals( "sn", equalityNode.getAttribute() );
        assertEquals( "Jagger", equalityNode.getValue().getString() );
    }


    @Test
    public void decodeComplexFilter() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x77 );
        stream.put( new byte[]
            {
                0x30, 0x53,
                  0x02, 0x01, 0x02,
                  0x63, 0x4E,
                    0x04, 0x11,
                    'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    0x0A, 0x01, 0x02,
                    0x0A, 0x01, 0x00,
                    0x02, 0x01, 0x00,
                    0x02, 0x01, 0x00,
                    0x01, 0x01, 0x00,
                    ( byte ) 0xA0, 0x28,
                      ( byte ) 0xA1, 0x1F,
                        ( byte ) 0xA0, 0x1D,
                          ( byte ) 0xA3, 0x1B,
                            0x04, 0x0B,
                              'o', 'b', 'j', 'e', 'c', 't', 'c', 'l', 'a', 's', 's',
                            0x04, 0x0C,
                              'g', 'r', 'o', 'u', 'p', 'o', 'f', 'n', 'a', 'm', 'e', 's',
                      ( byte ) 0x87, 0x05,
                        'o', 'w', 'n', 'e', 'r',
                    0x30, 0x00
        } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();

        assertEquals( 2, searchRequest.getMessageId() );
        assertEquals( "dc=example,dc=com", searchRequest.getBase().toString() );
        assertEquals( SearchScope.SUBTREE, searchRequest.getScope() );
        assertEquals( AliasDerefMode.NEVER_DEREF_ALIASES, searchRequest.getDerefAliases() );
        assertEquals( 0, searchRequest.getSizeLimit() );
        assertEquals( 0, searchRequest.getTimeLimit() );
        assertEquals( false, searchRequest.getTypesOnly() );

        ExprNode filter = searchRequest.getFilter();

        // (&(...
        AndNode andNode = ( AndNode ) filter;
        assertNotNull( andNode );

        List<ExprNode> andNodes = andNode.getChildren();
        assertEquals( 2, andNodes.size() );

        // (&(|(...
        filter = searchRequest.getFilter();

        OrNode orNode = ( OrNode ) andNodes.get( 0 );
        assertNotNull( orNode );

        List<ExprNode> orNodes = orNode.getChildren();
        assertEquals( 1, orNodes.size() );

        // (&(|(&...
        AndNode andNode2 = ( AndNode ) orNodes.get( 0 );
        assertNotNull( andNode2 );

        List<ExprNode> andNodes2 = andNode2.getChildren();
        assertEquals( 1, andNodes2.size() );

        // (&(|(&(objectClass=groupOfNames)
        EqualityNode<?> equalityNode = ( EqualityNode<?> ) andNodes2.get( 0 );
        assertNotNull( equalityNode );

        assertEquals( "objectclass", equalityNode.getAttribute() );
        assertEquals( "groupofnames", equalityNode.getValue().getString() );

        // (&(|(&(objectClass=groupOfNames)))(owner=*))
        PresenceNode presenceNode = ( PresenceNode ) andNodes.get( 1 );
        assertNotNull( presenceNode );

        assertEquals( "owner", presenceNode.getAttribute() );
    }
}
