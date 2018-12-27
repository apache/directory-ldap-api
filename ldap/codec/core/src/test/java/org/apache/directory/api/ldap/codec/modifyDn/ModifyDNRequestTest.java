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
package org.apache.directory.api.ldap.codec.modifyDn;


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
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the ModifyDNRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ModifyDNRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a full ModifyDNRequest
     */
    @Test
    public void testDecodeModifyDNRequestSuccess() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x48 );

        stream.put( new byte[]
            {
                0x30, 0x46,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x41,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,   // deleteoldrdn BOOLEAN,
                    ( byte ) 0x80, 0x09,// newSuperior [0] LDAPDN OPTIONAL }
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );
        assertEquals( "ou=system", modifyDnRequest.getNewSuperior().toString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a bad Dn ModifyDNRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestBadDN() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x48 );

        stream.put( new byte[]
            {
                0x30, 0x46,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x41,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', ':', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,   // deleteoldrdn BOOLEAN,
                    ( byte ) 0x80, 0x09,// newSuperior [0] LDAPDN OPTIONAL }
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof ModifyDnResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( ModifyDnResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of a bad Rdn ModifyDNRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestBadRDN() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x48 );

        stream.put( new byte[]
            {
                0x30, 0x46,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x41,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', ':', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,   // deleteoldrdn BOOLEAN,
                    ( byte ) 0x80, 0x09,// newSuperior [0] LDAPDN OPTIONAL }
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof ModifyDnResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( ModifyDnResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of a bad Rdn ModifyDNRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestBadNewSuperior() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x48 );

        stream.put( new byte[]
            {
                0x30, 0x46,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x41,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,   // deleteoldrdn BOOLEAN,
                    ( byte ) 0x80, 0x09,// newSuperior [0] LDAPDN OPTIONAL }
                      'o', 'u', ':', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof ModifyDnResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( ModifyDnResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of a full ModifyDNRequest with controls
     */
    @Test
    public void testDecodeModifyDNRequestSuccessWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x65 );

        stream.put( new byte[]
            {
                0x30, 0x63,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x41,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,   // deleteoldrdn BOOLEAN,
                    ( byte ) 0x80, 0x09,// newSuperior [0] LDAPDN OPTIONAL }
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                  ( byte ) 0xA0, 0x1B,      // A control
                  0x30, 0x19,
                    0x04, 0x17,
                      '2', '.', '1', '6', '.', '8', '4', '0', '.', '1',  '.', '1', '1', '3', '7', '3', '0',
                      '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );
        assertEquals( "ou=system", modifyDnRequest.getNewSuperior().toString() );

        // Check the Control
        Map<String, Control> controls = modifyDnRequest.getControls();

        assertEquals( 1, controls.size() );

        Control control = modifyDnRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyDNRequest without a superior
     */
    @Test
    public void testDecodeModifyDNRequestWithoutSuperior() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3D );

        stream.put( new byte[]
            {
                0x30, 0x3B,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x36,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                                        // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00    // deleteoldrdn BOOLEAN,
                                        // newSuperior [0] LDAPDN OPTIONAL }
        } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyDNRequest without a superior with controls
     */
    @Test
    public void testDecodeModifyDNRequestWithoutSuperiorWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x5A );

        stream.put( new byte[]
            {
                0x30, 0x58,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x6C, 0x36,               // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                            // ...
                                            // ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
                    0x04, 0x20,             // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',

                    0x04, 0x0F,             // newrdn RelativeLDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x01, 0x00,       // deleteoldrdn BOOLEAN,
                                            // newSuperior [0] LDAPDN OPTIONAL }
                  ( byte ) 0xA0, 0x1B,      // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1',  '.', '1', '1', '3', '7', '3', '0',
                        '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a ModifyRequest Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );

        // Check the Control
        Map<String, Control> controls = modifyDnRequest.getControls();

        assertEquals( 1, controls.size() );

        assertTrue( modifyDnRequest.hasControl( "2.16.840.1.113730.3.4.2" ) );

        Control control = modifyDnRequest.getControl( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a ModifyDNRequest with an empty body
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestEmptyBody() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                0x30, 0x05,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x00            // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        // Decode a ModifyDNRequest PDU
        ldapDecoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty entry
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestEmptyEntry() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            {
                0x30, 0x07,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x02,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                    0x04, 0x00          // ldapDN
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        // Decode a ModifyDNRequest PDU
        ldapDecoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty newRdn
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestEmptyNewRdn() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x2D );

        stream.put( new byte[]
            {
                0x30, 0x2B,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x26,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                                        // ...
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x00          // newRDN
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        // Decode a ModifyDNRequest PDU
        ldapDecoder.decode( stream, ldapMessageContainer );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty deleteOldRdn
     */
    @Test( expected=DecoderException.class )
    public void testDecodeModifyDNRequestEmptyDeleteOldRdnn() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3C );

        stream.put( new byte[]
            {
                0x30, 0x3A,             // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x6C, 0x35,           // CHOICE { ..., modifyDNRequest ModifyDNRequest,
                    // ...
                    0x04, 0x20,         // entry LDAPDN,
                      'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y',
                      ',', 'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',',
                      'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                    0x04, 0x0F,         // newRDN
                      'c', 'n', '=', 't', 'e', 's', 't', 'D', 'N', 'M', 'o', 'd', 'i', 'f', 'y',
                    0x01, 0x00          // deleteoldrdn BOOLEAN
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainerDirect<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainerDirect<>( codec );

        // Decode a ModifyDNRequest PDU
        ldapDecoder.decode( stream, ldapMessageContainer );
    }
}
