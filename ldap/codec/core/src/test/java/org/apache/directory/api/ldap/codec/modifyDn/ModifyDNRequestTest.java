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
package org.apache.directory.api.ldap.codec.modifyDn;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the ModifyDNRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ModifyDNRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a full ModifyDNRequest
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccess() throws DecoderException, EncoderException
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );
        assertEquals( "ou=system", modifyDnRequest.getNewSuperior().toString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a bad Dn ModifyDNRequest
     */
    @Test
    public void testDecodeModifyDNRequestBadDN()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
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
        } );
    }


    /**
     * Test the decoding of a bad Rdn ModifyDNRequest
     */
    @Test
    public void testDecodeModifyDNRequestBadRDN()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
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
        } );
    }


    /**
     * Test the decoding of a bad Rdn ModifyDNRequest
     */
    @Test
    public void testDecodeModifyDNRequestBadNewSuperior()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        assertThrows( DecoderException.class, ( ) ->
        {
            try
            {
                Asn1Decoder.decode( stream, ldapMessageContainer );
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
        } );
    }


    /**
     * Test the decoding of a full ModifyDNRequest with controls
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeModifyDNRequestSuccessWithControls() throws DecoderException, EncoderException
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

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

        LdapEncoder.encodeMessage( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyDNRequest without a superior
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeModifyDNRequestWithoutSuperior() throws DecoderException, EncoderException
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

        ModifyDnRequest modifyDnRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, modifyDnRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", modifyDnRequest.getName().toString() );
        assertEquals( false, modifyDnRequest.getDeleteOldRdn() );
        assertEquals( "cn=testDNModify", modifyDnRequest.getNewRdn().toString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ModifyDNRequest without a superior with controls
     * 
     * @throws DecoderException If the ASN1 decoding failed
     * @throws EncoderException If the ASN1 encoding failed
     */
    @Test
    public void testDecodeModifyDNRequestWithoutSuperiorWithControls() throws DecoderException, EncoderException
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        Asn1Decoder.decode( stream, ldapMessageContainer );

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

        LdapEncoder.encodeMessage( buffer, codec, modifyDnRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a ModifyDNRequest with an empty body
     */
    @Test
    public void testDecodeModifyDNRequestEmptyBody()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyDNRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty entry
     */
    @Test
    public void testDecodeModifyDNRequestEmptyEntry()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyDNRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty newRdn
     */
    @Test
    public void testDecodeModifyDNRequestEmptyNewRdn()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyDNRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }


    /**
     * Test the decoding of a ModifyDNRequest with an empty deleteOldRdn
     */
    @Test
    public void testDecodeModifyDNRequestEmptyDeleteOldRdnn()
    {
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
        LdapMessageContainer<ModifyDnRequest> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a ModifyDNRequest PDU
        assertThrows( DecoderException.class, ( ) ->
        {
            Asn1Decoder.decode( stream, ldapMessageContainer );
        } );
    }
}
