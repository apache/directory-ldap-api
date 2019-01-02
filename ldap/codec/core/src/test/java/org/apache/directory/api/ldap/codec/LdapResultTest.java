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
package org.apache.directory.api.ldap.codec;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Collection;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.AddResponseImpl;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ReferralImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * A test for LdapResults. We will use a AddResponse message to test the
 * LdapResult part
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class LdapResultTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a AddResponse with no LdapResult
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAddResponseEmptyResultCode() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x10 );

        stream.put( new byte[]
            {
                0x30, 0x0E,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x02,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x00              // Empty resultCode
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode a AddResponse message
        Asn1Decoder.decode( stream, container );
    }


    /**
     * Test the decoding of a AddResponse with no LdapResult
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAddResponseEmptyResultCodeAbove90() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0A );

        stream.put( new byte[]
            {
                0x30, 0x08,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x03,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x7F        // resultCode too high
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode a AddResponse message
        Asn1Decoder.decode( stream, container );
    }


    /**
     * Test the decoding of a AddResponse with all the different result codes
     */
    @Test
    public void testDecodeAddResponseEmptyResultCodesOK() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        byte[] buffer = new byte[]
            {
                0x30, 0x0C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x07,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x00,       // resultCode success
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00              // errorMessage LDAPString,
            };

        for ( int i = 0; i < 91; i++ )
        {
            buffer[9] = ( byte ) i;
            stream.put( buffer );
            stream.flip();

            // Allocate a LdapMessage Container
            LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

            // Decode a AddResponse PDU
            Asn1Decoder.decode( stream, container );

            stream.clear();
        }

        assertTrue( true );
    }


    /**
     * Test the decoding of a AddResponse with no matched Dn
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAddResponseEmptyResultCodeNoMatchedDN() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0A );

        stream.put( new byte[]
            {
                0x30, 0x08,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x69, 0x03,           // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x00,   // resultCode success
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode a AddResponse message
        Asn1Decoder.decode( stream, container );
    }


    /**
     * Test the decoding of a AddResponse with no error message
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAddResponseEmptyResultCodeNoErrorMsg() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0C );

        stream.put( new byte[]
            {
                0x30, 0x0A,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x69, 0x05,           // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x00,   // resultCode success
                    0x04, 0x00          // Empty matched Dn
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode a AddResponse message
        Asn1Decoder.decode( stream, container );
    }


    /**
     * Test the decoding of a AddResponse with a valid LdapResult
     */
    @Test
    public void testDecodeAddResponseEmptyResultCodeOK() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x30, 0x0C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x07,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x00,       // resultCode success
                    0x04, 0x00,             // Empty matched Dn
                    0x04, 0x00              // Empty errorMessage
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode the AddResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded AddResponse
        AddResponse addResponse = container.getMessage();

        assertEquals( 1, addResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, addResponse.getLdapResult().getResultCode() );
        assertEquals( "", addResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", addResponse.getLdapResult().getDiagnosticMessage() );

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        AddResponse response = new AddResponseImpl( addResponse.getMessageId() );
        response.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, response );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a AddResponse with a valid LdapResult with referral
     */
    @Test
    public void testDecodeAddResponseEmptyResultCodeOKReferral() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x1A );

        stream.put( new byte[]
            {
                0x30, 0x18,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x13,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x0A,       // resultCode success (Referral)
                    0x04, 0x00,             // Empty matched Dn
                    0x04, 0x00,             // Empty errorMessage
                    ( byte ) 0xA3, 0x0A,
                      0x04, 0x08,
                        'l', 'd', 'a', 'p', ':', '/', '/', '/',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode the AddResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded AddResponse
        AddResponse addResponse = container.getMessage();

        assertEquals( 1, addResponse.getMessageId() );
        assertEquals( ResultCodeEnum.REFERRAL, addResponse.getLdapResult().getResultCode() );
        assertEquals( "", addResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", addResponse.getLdapResult().getDiagnosticMessage() );

        Referral referral = addResponse.getLdapResult().getReferral();

        assertNotNull( referral );
        assertEquals( 1, referral.getLdapUrls().size() );
        Collection<String> ldapUrls = referral.getLdapUrls();

        assertTrue( ldapUrls.contains( "ldap:///" ) );

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        AddResponse response = new AddResponseImpl( addResponse.getMessageId() );
        Referral referralResult = new ReferralImpl();
        referralResult.addLdapUrl( "ldap:///" );

        response.getLdapResult().setReferral( referralResult );
        response.getLdapResult().setResultCode( ResultCodeEnum.REFERRAL );

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, response );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a AddResponse with a valid LdapResult with referrals
     */
    @Test
    public void testDecodeAddResponseEmptyResultCodeOKReferrals() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x24 );

        stream.put( new byte[]
            {
                0x30, 0x22,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x1D,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x0A,       // resultCode success (Referral)
                    0x04, 0x00,             // Empty matched Dn
                    0x04, 0x00,             // Empty errorMessage
                    ( byte ) 0xA3, 0x14,
                      0x04, 0x08,
                        'l', 'd', 'a', 'p', ':', '/', '/', '/',
                      0x04, 0x08,
                        'l', 'd', 'a', 'p', ':', '/', '/', '/',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode the AddResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded AddResponse
        AddResponse addResponse = container.getMessage();

        assertEquals( 1, addResponse.getMessageId() );
        assertEquals( ResultCodeEnum.REFERRAL, addResponse.getLdapResult().getResultCode() );
        assertEquals( "", addResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", addResponse.getLdapResult().getDiagnosticMessage() );

        Referral referral = addResponse.getLdapResult().getReferral();

        assertNotNull( referral );

        assertEquals( 2, referral.getLdapUrls().size() );

        Collection<String> ldapUrls = referral.getLdapUrls();

        for ( String ldapUrl : ldapUrls )
        {
            assertEquals( "ldap:///", ldapUrl );
        }

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        AddResponse response = new AddResponseImpl( addResponse.getMessageId() );
        Referral referralResult = new ReferralImpl();
        referralResult.addLdapUrl( "ldap:///" );
        referralResult.addLdapUrl( "ldap:///" );

        response.getLdapResult().setReferral( referralResult );
        response.getLdapResult().setResultCode( ResultCodeEnum.REFERRAL );

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, response );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a AddResponse with a valid LdapResult with referrals
     * and an empty referral
     */
    @Test
    public void testDecodeAddResponseEmptyResultCodeEmptyReferral() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x1C );

        stream.put( new byte[]
            {
                0x30, 0x1A,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x15,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x0A,       // resultCode success (Referral)
                    0x04, 0x00,             // Empty matched Dn
                    0x04, 0x00,             // Empty errorMessage
                    ( byte ) 0xA3, 0x0C,
                      0x04, 0x08,
                        'l', 'd', 'a', 'p', ':', '/', '/', '/',
                      0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode the AddResponse PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded AddResponse
        AddResponse addResponse = container.getMessage();

        assertEquals( 1, addResponse.getMessageId() );
        assertEquals( ResultCodeEnum.REFERRAL, addResponse.getLdapResult().getResultCode() );
        assertEquals( "", addResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", addResponse.getLdapResult().getDiagnosticMessage() );

        Referral referral = addResponse.getLdapResult().getReferral();

        assertNotNull( referral );

        assertEquals( 2, referral.getLdapUrls().size() );

        Collection<String> ldapUrls = referral.getLdapUrls();

        String[] expected = new String[]
            { "ldap:///", "" };
        int i = 0;

        for ( String ldapUrl : ldapUrls )
        {
            assertEquals( expected[i], ldapUrl );
            i++;
        }

        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        AddResponse response = new AddResponseImpl( addResponse.getMessageId() );
        Referral referralResult = new ReferralImpl();
        referralResult.addLdapUrl( "ldap:///" );
        referralResult.addLdapUrl( "" );

        response.getLdapResult().setReferral( referralResult );
        response.getLdapResult().setResultCode( ResultCodeEnum.REFERRAL );

        ByteBuffer result = LdapEncoder.encodeMessage( buffer, codec, response );

        assertArrayEquals( stream.array(), result.array() );
    }


    /**
     * Test the decoding of a AddResponse with a valid LdapResult and an invalid
     * transition after the referral sequence
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAddResponseEmptyResultCodeEmptyReferrals() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x10 );

        stream.put( new byte[]
            {
                0x30, 0x0E,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x69, 0x09,               // CHOICE { ..., addResponse AddResponse, ...
                    0x0A, 0x01, 0x0A,       // resultCode success (Referral)
                    0x04, 0x00,             // Empty matched Dn
                    0x04, 0x00,             // Empty errorMessage
                  ( byte ) 0xA3, 0x00,
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<AddResponse> container = new LdapMessageContainer<>( codec );

        // Decode the AddResponse PDU
        Asn1Decoder.decode( stream, container );
    }
}
