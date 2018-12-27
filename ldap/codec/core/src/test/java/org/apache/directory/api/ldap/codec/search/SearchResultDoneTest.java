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
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the SearchResultDone codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SearchResultDoneTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a SearchResultDone
     */
    @Test
    public void testDecodeSearchResultDoneSuccess() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x30, 0x0C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x65, 0x07,               // CHOICE { ..., searchResDone SearchResultDone, ...
                                            // SearchResultDone ::= [APPLICATION 5] LDAPResult
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00              // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
            } );

        stream.flip();

        // Allocate a SearchResultDone Container
        LdapMessageContainerDirect<SearchResultDone> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        SearchResultDone searchResultDone = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultDone.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, searchResultDone.getLdapResult().getResultCode() );
        assertEquals( "", searchResultDone.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", searchResultDone.getLdapResult().getDiagnosticMessage() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, searchResultDone );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchResultDone with controls
     */
    @Test
    public void testDecodeSearchResultDoneSuccessWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3C );

        stream.put( new byte[]
            {
                0x30, 0x3A,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x65, 0x07,               // CHOICE { ..., searchResDone SearchResultDone, ...
                                            // SearchResultDone ::= [APPLICATION 5] LDAPResult
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,              // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
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

        // Allocate a BindRequest Container
        LdapMessageContainerDirect<SearchResultDone> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        SearchResultDone searchResultDone = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultDone.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, searchResultDone.getLdapResult().getResultCode() );
        assertEquals( "", searchResultDone.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", searchResultDone.getLdapResult().getDiagnosticMessage() );

        // Check the Control
        Map<String, Control> controls = searchResultDone.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "1.2.840.113556.1.4.319" );
        assertEquals( "1.2.840.113556.1.4.319", control.getOid() );
        assertTrue( control instanceof PagedResults );

        PagedResults pagedSearchControl = ( PagedResults ) control;

        assertEquals( 5, pagedSearchControl.getSize() );
        assertArrayEquals( Strings.getBytesUtf8( "abcdef" ), pagedSearchControl.getCookie() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, searchResultDone );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a SearchResultDone with no LdapResult
     */
    @Test( expected=DecoderException.class )
    public void testDecodeSearchResultDoneEmptyResult() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x65, 0x00            // CHOICE { ..., searchResDone SearchResultDone, ...
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainerDirect<SearchResultDone> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        // Decode a SearchResultDone message
        ldapDecoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a SearchResultDone with a result code of length 2 bytes
     */
    @Test
    public void testDecodeSearchResultDoneEsyncRefresh() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0F );

        stream.put( new byte[]
            {
                0x30, 0x0D,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x65, 0x08,               // CHOICE { ..., searchResDone SearchResultDone, ...
                                            // SearchResultDone ::= [APPLICATION 5] LDAPResult
                    0x0A, 0x02, 0x10, 0x00, // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // eSyncRefreshRequired (4096), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00              // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
            } );

        stream.flip();

        // Allocate a SearchResultDone Container
        LdapMessageContainerDirect<SearchResultDone> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        SearchResultDone searchResultDone = ldapMessageContainer.getMessage();

        assertEquals( 1, searchResultDone.getMessageId() );
        assertEquals( ResultCodeEnum.E_SYNC_REFRESH_REQUIRED, searchResultDone.getLdapResult().getResultCode() );
        assertEquals( "", searchResultDone.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", searchResultDone.getLdapResult().getDiagnosticMessage() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, searchResultDone );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
