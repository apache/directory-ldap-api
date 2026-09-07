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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the SearchRequest filter decoder only accepts a filter element
 * at the structural (TLV) position the grammar state implies. A filter TLV
 * physically nested inside another filter element's TLV must be rejected
 * instead of being attached as a sibling of the enclosing element (filter
 * structure smuggling / parser differential).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SearchRequestFilterNestingTest extends AbstractCodecServiceTest
{
    /**
     * A valid flat and-filter (&amp;(a=b)(c=d)) must still decode.
     *
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodeValidSiblingFilters() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x2E,                   // searchRequest SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x09,                 // baseObject LDAPDN,
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED baseObject
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED never
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER 0
                    0x02, 0x01, 0x00,           // timeLimit INTEGER 0
                    0x01, 0x01, 0x00,           // typesOnly BOOLEAN false
                    ( byte ) 0xA0, 0x10,        // filter and [0] SET OF Filter
                      ( byte ) 0xA3, 0x06,      // equalityMatch [3] (a=b)
                        0x04, 0x01, 'a',
                        0x04, 0x01, 'b',
                      ( byte ) 0xA3, 0x06,      // equalityMatch [3] (c=d), a real sibling
                        0x04, 0x01, 'c',
                        0x04, 0x01, 'd',
                    0x30, 0x00                  // attributes AttributeDescriptionList (empty)
            } );

        stream.flip();

        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        assertEquals( TLVStateEnum.PDU_DECODED, ldapMessageContainer.getState() );

        SearchRequest searchRequest = ldapMessageContainer.getMessage();
        ExprNode filter = searchRequest.getFilter();
        List<ExprNode> children = ( ( AndNode ) filter ).getChildren();
        assertEquals( 2, children.size() );
    }


    /**
     * The same PDU, but the second equalityMatch TLV is physically nested
     * INSIDE the first equalityMatch element's TLV (the first element's
     * length is enlarged to cover it). Byte-count bookkeeping still
     * balances, but a conformant parser rejects the PDU; the decoder must
     * not silently attach the smuggled element as a sibling filter.
     *
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodeSmuggledNestedFilterRejected()
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                  0x63, 0x2E,                   // searchRequest SearchRequest ::= APPLICATION[3] SEQUENCE {
                    0x04, 0x09,                 // baseObject LDAPDN,
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x0A, 0x01, 0x00,           // scope ENUMERATED baseObject
                    0x0A, 0x01, 0x00,           // derefAliases ENUMERATED never
                    0x02, 0x01, 0x00,           // sizeLimit INTEGER 0
                    0x02, 0x01, 0x00,           // timeLimit INTEGER 0
                    0x01, 0x01, 0x00,           // typesOnly BOOLEAN false
                    ( byte ) 0xA0, 0x10,        // filter and [0] SET OF Filter
                      ( byte ) 0xA3, 0x0E,      // equalityMatch [3], length covers the smuggled TLV
                        0x04, 0x01, 'a',
                        0x04, 0x01, 'b',
                        ( byte ) 0xA3, 0x06,    // smuggled equalityMatch INSIDE the previous element
                          0x04, 0x01, 'c',
                          0x04, 0x01, 'd',
                    0x30, 0x00                  // attributes AttributeDescriptionList (empty)
            } );

        stream.flip();

        LdapMessageContainer<SearchRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class,
            () -> Asn1Decoder.decode( stream, ldapMessageContainer ) );
    }
}
