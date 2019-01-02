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
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.cancel.CancelFactory;
import org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsFactory;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the ExtendedRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ExtendedRequestTest extends AbstractCodecServiceTest
{
    @Before
    public void init()
    {
        codec.getExtendedRequestFactories().put( "1.3.6.1.1.8", new CancelFactory( codec ) );
        codec.getExtendedRequestFactories().put( "1.3.6.1.4.1.1466.20037", new StartTlsFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a full ExtendedRequest
     */
    @Test
    public void testDecodeExtendedRequestSuccess() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1B );

        stream.put( new byte[]
            { 
                0x30, 0x19,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x14,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                  ( byte ) 0x80, 0x0B,
                    '1', '.', '3', '.', '6', '.', '1', '.', '1', '.', '8',
                                            // requestValue [1] OCTET STRING OPTIONAL }
                  ( byte ) 0x81, 0x05,
                    0x30, 0x03,
                      0x02, 0x01, 0x01
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedRequest PDU
        ExtendedRequest extendedRequest = container.getMessage();

        assertTrue( extendedRequest instanceof CancelRequest );
        
        CancelRequest cancelRequest = ( CancelRequest ) extendedRequest;
        
        assertEquals( 1, cancelRequest.getMessageId() );
        assertEquals( "1.3.6.1.1.8", cancelRequest.getRequestName() );
        assertEquals( 1, cancelRequest.getCancelId() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, cancelRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full ExtendedRequest with controls
     */
    @Test
    public void testDecodeExtendedRequestWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x38 );

        stream.put( new byte[]
            { 
                0x30, 0x36,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                                                // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x14,                   // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                                // requestName [0] LDAPOID,
                    ( byte ) 0x80, 0x0B,
                      '1', '.', '3', '.', '6', '.', '1', '.', '1', '.', '8',
                                                // requestValue [1] OCTET STRING OPTIONAL }
                    ( byte ) 0x81, 0x05,
                      0x30, 0x03,
                        0x02, 0x01, 0x01,
                  ( byte ) 0xA0, 0x1B,          // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', 
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedRequest PDU
        ExtendedRequest extendedRequest = container.getMessage();

        assertTrue( extendedRequest instanceof CancelRequest );
        
        CancelRequest cancelRequest = ( CancelRequest ) extendedRequest;
        
        assertEquals( 1, cancelRequest.getMessageId() );
        assertEquals( "1.3.6.1.1.8", cancelRequest.getRequestName() );
        assertEquals( 1, cancelRequest.getCancelId() );

        // Check the Control
        Map<String, Control> controls = extendedRequest.getControls();

        assertEquals( 1, controls.size() );
        assertTrue( extendedRequest.hasControl( "2.16.840.1.113730.3.4.2" ) );

        Control control = extendedRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, cancelRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full ExtendedRequest with no value and with
     * controls
     */
    @Test
    public void testDecodeExtendedRequestNoValueWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3C );

        stream.put( new byte[]
            { 
                0x30, 0x3A,                     // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // messageID MessageID
                                                // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x18,                   // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                                // requestName [0] LDAPOID,
                    ( byte ) 0x80, 0x16,
                      '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                      '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
                                                // requestValue [1] OCTET STRING OPTIONAL }
                  ( byte ) 0xA0, 0x1B,          // A control
                    0x30, 0x19,
                      0x04, 0x17,
                       '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', 
                       '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedRequest PDU
        ExtendedRequest extendedRequest = container.getMessage();

        assertTrue( extendedRequest instanceof StartTlsRequest );
        StartTlsRequest startTlsRequest = ( StartTlsRequest ) extendedRequest;

        assertEquals( 1, startTlsRequest.getMessageId() );
        assertEquals( "1.3.6.1.4.1.1466.20037", startTlsRequest.getRequestName() );

        // Check the Control
        Map<String, Control> controls = extendedRequest.getControls();

        assertEquals( 1, controls.size() );

        assertTrue( extendedRequest.hasControl( "2.16.840.1.113730.3.4.2" ) );

        Control control = extendedRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, startTlsRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an empty ExtendedRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeExtendedRequestEmpty() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            { 
                0x30, 0x05,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x00,           // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of an empty OID
     */
    @Test( expected=DecoderException.class )
    public void testDecodeEmptyOID() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            { 
                0x30, 0x07,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                                        // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x02,           // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                    ( byte ) 0x80, 0x00 
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a bad name
     */
    @Test( expected=DecoderException.class )
    public void testDecodeExtendedBadRequestName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1F );

        stream.put( new byte[]
            { 
                0x30, 0x1D,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x18,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                    ( byte ) 0x80, 0x16,
                      '1', '-', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                      '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a name only ExtendedRequest
     */
    @Test
    public void testDecodeExtendedRequestName() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x1F );

        stream.put( new byte[]
            { 
                0x30, 0x1D,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x18,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                    ( byte ) 0x80, 0x16,
                      '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                      '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedRequest PDU
        ExtendedRequest extendedRequest = container.getMessage();

        assertTrue( extendedRequest instanceof StartTlsRequest );
        StartTlsRequest startTlsRequest = ( StartTlsRequest ) extendedRequest;

        assertEquals( 1, startTlsRequest.getMessageId() );
        assertEquals( "1.3.6.1.4.1.1466.20037", startTlsRequest.getRequestName() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, startTlsRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of an empty value ExtendedRequest
     */
    @Test
    public void testDecodeExtendedRequestEmptyNoValue() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x21 );

        stream.put( new byte[]
            { 
                0x30, 0x1F,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x1A,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                  ( byte ) 0x80, 0x16,
                    '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                    '1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
                                            // requestValue [1] OCTET STRING OPTIONAL }
                  ( byte ) 0x81, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the ExtendedRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded ExtendedRequest PDU
        ExtendedRequest extendedRequest = container.getMessage();
        
        assertTrue( extendedRequest instanceof StartTlsRequest );
        StartTlsRequest startTlsRequest = ( StartTlsRequest ) extendedRequest;

        assertEquals( 1, startTlsRequest.getMessageId() );
        assertEquals( "1.3.6.1.4.1.1466.20037", startTlsRequest.getRequestName() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, startTlsRequest );

        assertArrayEquals( 
            new byte[]
            { 
                0x30, 0x1D,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x18,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                  ( byte ) 0x80, 0x16,
                    '1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.', 
                    '1', '4', '6', '6', '.', '2', '0', '0', '3', '7'
                                            // requestValue [1] OCTET STRING OPTIONAL }
            }, buffer.getBytes().array() );
    }
}
