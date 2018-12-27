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
package org.apache.directory.api.ldap.codec.abandon;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AbandonRequestImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.Cascade;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test an AbandonRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AbandonRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a AbandonRequest with controls
     */
    @Test
    public void testDecodeAbandonRequestWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x9C );
        stream.put( new byte[]
            {
              0x30, (byte)0x81, (byte)0x99,             // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x03,                       // messageID MessageID
                0x50, 0x01, 0x02,                       // CHOICE { ..., abandonRequest
                ( byte ) 0xA0, (byte)0x81, (byte)0x90,  // controls [0] Controls OPTIONAL }
                  0x30, 0x2E,                           // Control ::= SEQUENCE {
                    0x04, 0x16,                         // controlType LDAPOID,
                                                        // SortRequest
                      '1', '.', '2', '.', '8', '4', '0', '.', 
                      '1', '1', '3', '5', '5', '6', '.', '1', 
                      '.', '4', '.', '4', '7', '3',
                    0x01, 0x01, ( byte ) 0xFF,          // criticality BOOLEAN DEFAULT FALSE,
                    0x04, 0x11,                         // controlValue OCTET STRING OPTIONAL }
                      0x30, 0x0F,                       // SortKeyList ::= SEQUENCE OF SEQUENCE {
                        0x30, 0x07,                     // SEQUENCE
                          0x04, 0x02,                   // attributeType   AttributeDescription,
                            'c', 'n',
                          (byte)0x81, 0x01, (byte)0xFF, // reverseOrder    [1] BOOLEAN DEFAULT FALSE }
                        0x30, 0x04,                     // SEQUENCE
                          0x04, 0x02,                   // attributeType   AttributeDescription,
                            's', 'n',
                  0x30, 0x25,                           // Control ::= SEQUENCE {
                    0x04, 0x16,                         // controlType LDAPOID,
                                                        // PagedResults
                      '1', '.', '2', '.', '8', '4', '0', '.', 
                      '1', '1', '3', '5', '5', '6', '.', '1', 
                      '.', '4', '.', '3', '1', '9',
                    0x04, 0x0B,                         // controlValue OCTET STRING OPTIONAL }
                      0x30, 0x09,                       // realSearchControlValue ::= SEQUENCE {
                        0x02, 0x01, 0x10,               // size            INTEGER (0..maxInt),
                        0x04, 0x04,                     // cookie          OCTET STRING
                          't', 't', 't', 't',
                  0x30, 0x1C,                           // Control ::= SEQUENCE {
                    0x04, 0x17,                         // controlType LDAPOID,
                                                        // ManageDsaIT
                      '2', '.', '1', '6', '.', '8', '4', '0', 
                      '.', '1', '.', '1', '1', '3', '7', '3', 
                      '0', '.', '3', '.', '4', '.', '2',
                    0x01, 0x01, ( byte ) 0xFF,          // criticality BOOLEAN DEFAULT FALSE }
                  0x30, 0x19,                           // Control ::= SEQUENCE {
                    0x04, 0x17,                         // controlType LDAPOID} 
                                                        // Cascade
                      '1', '.', '3', '.', '6', '.', '1', '.', 
                      '4', '.', '1', '.', '1', '8', '0', '6', 
                      '0', '.', '0', '.', '0', '.', '1'
            } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        LdapMessageContainerDirect<AbandonRequest>  container = new LdapMessageContainerDirect<>( codec );

        // Decode the PDU
        ldapDecoder.decode( stream, container );

        // Check that everything is OK
        AbandonRequest abandonRequest = container.getMessage();

        // Copy the message
        AbandonRequest internalAbandonRequest = new AbandonRequestImpl( abandonRequest.getAbandoned() );
        internalAbandonRequest.setMessageId( abandonRequest.getMessageId() );

        assertEquals( 3, abandonRequest.getMessageId() );
        assertEquals( 2, abandonRequest.getAbandoned() );

        // Check the Controls
        Map<String, Control> controls = abandonRequest.getControls();

        assertEquals( 4, controls.size() );

        Control control = controls.get( "1.2.840.113556.1.4.473" );
        assertEquals( "1.2.840.113556.1.4.473", control.getOid() );
        assertTrue( control instanceof SortRequest );
        assertTrue( control.isCritical() );
        assertEquals( 2, ( ( SortRequest ) control ).getSortKeys().size() );
        internalAbandonRequest.addControl( control );

        control = controls.get( "1.2.840.113556.1.4.319" );
        assertEquals( "1.2.840.113556.1.4.319", control.getOid() );
        assertTrue( control instanceof PagedResults );
        assertFalse( control.isCritical() );
        internalAbandonRequest.addControl( control );

        control = controls.get( "2.16.840.1.113730.3.4.2" );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertTrue( control instanceof ManageDsaIT );
        assertTrue( control.isCritical() );
        internalAbandonRequest.addControl( control );

        control = controls.get( "1.3.6.1.4.1.18060.0.0.1" );
        assertEquals( "1.3.6.1.4.1.18060.0.0.1", control.getOid() );
        assertTrue( control instanceof Cascade );
        assertFalse( control.isCritical() );
        internalAbandonRequest.addControl( control );

        // Check reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();
        LdapEncoder.encodeMessageReverse( buffer, codec, internalAbandonRequest );

        // Check that the decoded messages are equals
        LdapMessageContainerDirect<AbandonRequest>  ldapMessageContainer2 =
            new LdapMessageContainerDirect<> ( codec );

        // Decode the PDU
        ldapDecoder.decode( buffer.getBytes(), ldapMessageContainer2 );

        // Check that everything is OK
        AbandonRequest abandonRequest3 = container.getMessage();
        
        assertEquals( abandonRequest, abandonRequest3 );
    }


    /**
     * Test the decoding of a AbandonRequest with no controls
     */
    @Test
    public void testDecodeAbandonRequestNoControlsHighMessageId() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0A );
        stream.put( new byte[]
            {
              0x30, 0x08,                                   // LDAPMessage ::=SEQUENCE {
                0x02, 0x03, 0x00, ( byte ) 0x80, 0x13,      // messageID MessageID
                0x50, 0x01, 0x02                            // CHOICE { ..., abandonRequest
                                                            // AbandonRequest,...
                                                            // AbandonRequest ::= [APPLICATION 16] MessageID
            } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        LdapMessageContainerDirect<AbandonRequest>  container = new LdapMessageContainerDirect<>( codec );

        // Decode the PDU
        ldapDecoder.decode( stream, container );

        // Check that everything is OK
        AbandonRequest abandonRequest = container.getMessage();

        assertEquals( 32787, abandonRequest.getMessageId() );
        assertEquals( 2, abandonRequest.getAbandoned() );

        // Check the length
        AbandonRequest internalAbandonRequest = new AbandonRequestImpl( abandonRequest.getAbandoned() );
        internalAbandonRequest.setMessageId( abandonRequest.getMessageId() );


        // Check the reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();
        LdapEncoder.encodeMessageReverse( buffer, codec, internalAbandonRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a AbandonRequest with a null messageId
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAbandonRequestNoMessageId() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0A );
        stream.put( new byte[]
            {
              0x30, 0x08,               // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                0x50, 0x00              // CHOICE { ..., abandonRequest AbandonRequest,...
                                        // AbandonRequest ::= [APPLICATION 16] MessageID
            } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        LdapMessageContainerDirect<AbandonRequest> container = new LdapMessageContainerDirect<>( codec );

        // Decode the PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a AbandonRequest with a bad Message Id
     */
    @Test( expected=DecoderException.class )
    public void testDecodeAbandonRequestBadMessageId() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0B );
        stream.put( new byte[]
            {
              0x30, 0x09,                   // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,           // messageID MessageID
                0x50, 0x01, ( byte ) 0xFF   // CHOICE { ..., abandonRequest AbandonRequest,...
                                            // AbandonRequest ::= [APPLICATION 16] MessageID
            } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        LdapMessageContainerDirect<AbandonRequest>  container = new LdapMessageContainerDirect<>( codec );

        // Decode the PDU
        ldapDecoder.decode( stream, container );
    }
}
