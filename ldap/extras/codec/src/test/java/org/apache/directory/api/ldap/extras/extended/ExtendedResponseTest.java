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
package org.apache.directory.api.ldap.extras.extended;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulDisconnectFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI.WhoAmIFactory;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the ExtendedResponse codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ExtendedResponseTest extends AbstractCodecServiceTest
{
    @Before
    public void init()
    {
        codec.getExtendedResponseFactories().put( "1.3.6.1.4.1.18060.0.1.5", new GracefulDisconnectFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a full ExtendedResponse
     */
    @Test
    public void testDecodeExtendedResponseSuccess() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x2E );

        stream.put( new byte[]
            {
                0x30, 0x2C,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp ExtendedResponse, ...
                  0x78, 0x27,               // ExtendedResponse ::= [APPLICATION 23] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x17,    //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                      '1', '8', '0', '6', '0', '.', '0', '.', '1', '.', '5',
                                            // response [11] OCTET STRING OPTIONAL }
                    ( byte ) 0x8B, 0x05,
                      0x30, 0x03,
                        ( byte ) 0x02, 0x01, 0x02
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();
        
        assertEquals( 1, extendedResponse.getMessageId() );
        assertTrue( extendedResponse instanceof GracefulDisconnectResponse );
        GracefulDisconnectResponse gracefulDisconnectResponse =( GracefulDisconnectResponse) extendedResponse;
        
        assertEquals( ResultCodeEnum.SUCCESS, gracefulDisconnectResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, gracefulDisconnectResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", gracefulDisconnectResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.4.1.18060.0.1.5", gracefulDisconnectResponse.getResponseName() );
        //assertEquals( 2, gracefulDisconnectResponse.getTimeOffline() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, gracefulDisconnectResponse );

        //assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full ExtendedResponse with controls
     */
    @Test
    public void testDecodeExtendedResponseSuccessWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x40 );

        stream.put( new byte[]
            {
                0x30, 0x3E,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                                                // CHOICE {
                                                //    ...,
                                                //    extendedResp ExtendedResponse,
                                                //    ...
                  0x78, 0x1D,                   // ExtendedResponse ::= [APPLICATION 23] SEQUENCE {
                                                //   COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,           // LDAPResult ::= SEQUENCE {
                                                // resultCode ENUMERATED {
                                                // success (0), ...
                                                // },
                    0x04, 0x00,                 // matchedDN LDAPDN,
                    0x04, 0x00,                 // errorMessage LDAPString,
                                                // referral [3] Referral OPTIONAL }
                                                // responseName [0] LDAPOID,
                                                //     referral [3] Referral OPTIONAL }
                    ( byte ) 0x8A, 0x0D,        //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                    ( byte ) 0x8B, 0x05,        // response [11] OCTET STRING OPTIONAL }
                      'v', 'a', 'l', 'u', 'e',
                    ( byte ) 0xA0, 0x1A,        // A control
                      0x30, 0x18,
                        0x04, 0x16,
                          '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6',
                          '.', '1', '.', '4', '.', '5', '2', '8'
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, extendedResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.5.5.2", extendedResponse.getResponseName() );
        assertEquals( "value", Strings.utf8ToString( extendedResponse.getResponseValue() ) );

        // Check the Control
        Map<String, Control> controls = extendedResponse.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( org.apache.directory.api.ldap.codec.api.CodecControl<Control> ) controls
            .get( "1.2.840.113556.1.4.528" );
        assertEquals( "1.2.840.113556.1.4.528", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x40, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of a ExtendedRequest with no name
     */
    @Test
    public void testDecodeExtendedRequestNoName() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x30, 0x0C,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x07,           // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                        // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,   // LDAPResult ::= SEQUENCE {
                                        // resultCode ENUMERATED {
                                        // success (0), ...
                                        // },
                    0x04, 0x00,         // matchedDN LDAPDN,
                    0x04, 0x00          // errorMessage LDAPString,
                                        // referral [3] Referral OPTIONAL }
                                        // responseName [0] LDAPOID,
        } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponse extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( "", extendedResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x0E, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of a ExtendedRequest with no name and a control
     */
    @Test
    public void testDecodeExtendedRequestNoNameWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x2A );

        stream.put( new byte[]
            {
                0x30, 0x28,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x07,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0xA0, 0x1A,    // A control
                    0x30, 0x18,
                      0x04, 0x16,
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6',
                        '.', '1', '.', '4', '.', '5', '2', '8'
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponse extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( "", extendedResponse.getLdapResult().getMatchedDn().getName() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );

        // Check the Control
        Map<String, Control> controls = extendedResponse.getControls();

        assertEquals( 1, controls.size() );
        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( org.apache.directory.api.ldap.codec.api.CodecControl<Control> ) controls
            .get( "1.2.840.113556.1.4.528" );
        assertEquals( "1.2.840.113556.1.4.528", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x2A, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of an empty ExtendedResponse
     */
    @Test( expected=DecoderException.class )
    public void testDecodeExtendedResponseEmpty() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x00                // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode a DelRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of an ExtendedResponse with an empty ResponseName
     */
    @Test( expected=DecoderException.class )
    public void testDecodeExtendedResponseEmptyResponseName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x10 );

        stream.put( new byte[]
            {
                0x30, 0x0E,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                                                // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x09,                   // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                                // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,           // LDAPResult ::= SEQUENCE {
                                                // resultCode ENUMERATED {
                                                // success (0), ...
                                                // },
                    0x04, 0x00,                 // matchedDN LDAPDN,
                    0x04, 0x00,                 // errorMessage LDAPString,
                                                // referral [3] Referral OPTIONAL }
                                                // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode a DelRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of an ExtendedResponse with a bad responseName
     */
    @Test( expected=DecoderException.class )
    public void testDecodeExtendedResponseBadOIDResponseName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x12 );

        stream.put( new byte[]
            {
                0x30, 0x10,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x0B,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x02,
                      'a', 'b'
               } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of an ExtendedResponse with no response
     */
    @Test
    public void testDecodeExtendedResponseNoResponse() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1D );

        stream.put( new byte[]
            {
                0x30, 0x1B,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x16,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x0D,    //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2'
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, extendedResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.5.5.2", extendedResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( extendedResponse.getResponseValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x1D, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of an ExtendedResponse with no response with controls
     */
    @Test
    public void testDecodeExtendedResponseNoResponseWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x39 );

        stream.put( new byte[]
            {
                0x30, 0x37,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x16,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x0D,    //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                  ( byte ) 0xA0, 0x1A,      // A control
                    0x30, 0x18,
                      0x04, 0x16,
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6',
                        '.', '1', '.', '4', '.', '5', '2', '8'
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, extendedResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.5.5.2", extendedResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( extendedResponse.getResponseValue() ) );

        // Check the Control
        Map<String, Control> controls = extendedResponse.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( org.apache.directory.api.ldap.codec.api.CodecControl<Control> ) controls
            .get( "1.2.840.113556.1.4.528" );
        assertEquals( "1.2.840.113556.1.4.528", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x39, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of an ExtendedResponse with an empty response
     */
    @Test
    public void testDecodeExtendedResponseEmptyResponse() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1F );

        stream.put( new byte[]
            {
                0x30, 0x1D,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x18,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x0D,    //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                    ( byte ) 0x8B, 0x00
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, extendedResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.5.5.2", extendedResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( extendedResponse.getResponseValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x1F, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }


    /**
     * Test the decoding of an ExtendedResponse with an empty response with
     * controls
     */
    @Test
    public void testDecodeExtendedResponseEmptyResponseWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3B );

        stream.put( new byte[]
            {
                0x30, 0x39,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedResp Response, ...
                  0x78, 0x18,               // ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
                                            // COMPONENTS OF LDAPResult,
                    0x0A, 0x01, 0x00,       // LDAPResult ::= SEQUENCE {
                                            // resultCode ENUMERATED {
                                            // success (0), ...
                                            // },
                    0x04, 0x00,             // matchedDN LDAPDN,
                    0x04, 0x00,             // errorMessage LDAPString,
                                            // referral [3] Referral OPTIONAL }
                                            // responseName [0] LDAPOID,
                    ( byte ) 0x8A, 0x0D,    //   responseName [10] LDAPOID OPTIONAL,
                      '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                    ( byte ) 0x8B, 0x00,
                  ( byte ) 0xA0, 0x1A,    // A control
                    0x30, 0x18,
                      0x04, 0x16,
                        '1', '.', '2', '.', '8', '4', '0', '.', '1', '1', '3', '5', '5', '6',
                        '.', '1', '.', '4', '.', '5', '2', '8'
            } );

        String decodedPdu = Strings.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedResponseDecorator<?>> container =
            new LdapMessageContainer<ExtendedResponseDecorator<?>>( codec );

        // Decode the ExtendedResponse PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedResponse PDU
        ExtendedResponseDecorator<?> extendedResponse = container.getMessage();

        assertEquals( 1, extendedResponse.getMessageId() );
        assertEquals( ResultCodeEnum.SUCCESS, extendedResponse.getLdapResult().getResultCode() );
        assertEquals( Dn.EMPTY_DN, extendedResponse.getLdapResult().getMatchedDn() );
        assertEquals( "", extendedResponse.getLdapResult().getDiagnosticMessage() );
        assertEquals( "1.3.6.1.5.5.2", extendedResponse.getResponseName() );
        assertEquals( "", Strings.utf8ToString( extendedResponse.getResponseValue() ) );

        // Check the Control
        Map<String, Control> controls = extendedResponse.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( org.apache.directory.api.ldap.codec.api.CodecControl<Control> ) controls
            .get( "1.2.840.113556.1.4.528" );
        assertEquals( "1.2.840.113556.1.4.528", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check the encoding
        ByteBuffer bb = LdapEncoder.encodeMessage( codec, extendedResponse );

        // Check the length
        assertEquals( 0x3B, bb.limit() );

        String encodedPdu = Strings.dumpBytes( bb.array() );

        assertEquals( encodedPdu, decodedPdu );
    }
}
