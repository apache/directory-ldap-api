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
package org.apache.directory.api.ldap.codec.modify;


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
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the ModifyResponse codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ModifyResponseTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a ModifyResponse
     */
    @Test
    public void testDecodeModifyResponseSuccess() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x30, 0x0C,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x67, 0x07,               // CHOICE { ..., modifyResponse ModifyResponse, ...
                                            // ModifyResponse ::= [APPLICATION 7] LDAPResult
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

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyResponse> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyResponse PDU
        ldapDecoder.decode( stream, ldapMessageContainer );

        // Check the decoded ModifyResponse PDU
        ModifyResponse modifyResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, modifyResponse.getLdapResult().getResultCode() );
        assertEquals( "", modifyResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", modifyResponse.getLdapResult().getDiagnosticMessage() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyResponse with controls
     */
    @Test
    public void testDecodeModifyResponseSuccessWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x32 );

        stream.put( new byte[]
            {
                0x30, 0x30,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x67, 0x07,               // CHOICE { ..., modifyResponse ModifyResponse, ...
                                            // ModifyResponse ::= [APPLICATION 7] LDAPResult
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // }
                  ( byte ) 0xA0, 0x22,      // A control
                    0x30, 0x20,
                      0x04, 0x17,           // EntryChange response control
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', 
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '7',
                      0x04, 0x05,           // Control value
                        0x30, 0x03,         // EntryChangeNotification ::= SEQUENCE {
                          0x0A, 0x01, 0x01  //     changeType ENUMERATED {
                                            //         add             (1),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyResponse> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyResponse PDU
        ldapDecoder.decode( stream, ldapMessageContainer );

        // Check the decoded ModifyResponse PDU
        ModifyResponse modifyResponse = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, modifyResponse.getLdapResult().getResultCode() );
        assertEquals( "", modifyResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", modifyResponse.getLdapResult().getDiagnosticMessage() );

        // Check the Control
        Map<String, Control> controls = modifyResponse.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.7" );
        assertTrue( control instanceof EntryChange);
        assertEquals( "2.16.840.1.113730.3.4.7", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyResponse );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyResponse with no LdapResult
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyResponseEmptyResult() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x67, 0x00,               // CHOICE { ..., modifyResponse ModifyResponse, ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ModifyResponse> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyResponse message
        ldapDecoder.decode( stream, ldapMessageContainer );
    }
}
