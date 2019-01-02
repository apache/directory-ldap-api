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
package org.apache.directory.api.ldap.codec.del;


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
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponseImpl;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the DelRequest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DelRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a full DelRequest
     */
    @Test
    public void testDecodeDelRequestSuccess() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x27 );

        stream.put( new byte[]
            {
              0x30, 0x25,               // LDAPMessage ::= SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                                        // CHOICE { ..., delRequest DelRequest, ...
                                        // DelRequest ::= [APPLICATION 10] LDAPDN;
                0x4A, 0x20,
                  'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y', ',',
                  'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteRequest> container = new LdapMessageContainer<>( codec );

        // Decode a DelRequest PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded DelRequest PDU
        DeleteRequest delRequest = container.getMessage();

        assertEquals( 1, delRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", delRequest.getName().toString() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, delRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a full DelRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeDelRequestBadDN() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x27 );

        stream.put( new byte[]
            {
              0x30, 0x25,               // LDAPMessage ::= SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                                        // CHOICE { ..., delRequest DelRequest, ...
                                        // DelRequest ::= [APPLICATION 10] LDAPDN;
                0x4A, 0x20,
                  'c', 'n', ':', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y', ',',
                  'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteRequest> container = new LdapMessageContainer<>( codec );

        // Decode a DelRequest PDU
        try
        {
            Asn1Decoder.decode( stream, container );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof DeleteResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( DeleteResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of an empty DelRequest
     */
    @Test( expected=DecoderException.class )
    public void testDecodeDelRequestEmpty() throws DecoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
              0x30, 0x05,               // LDAPMessage ::= SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                                        // CHOICE { ..., delRequest DelRequest, ...
                                        // DelRequest ::= [APPLICATION 10] LDAPDN;
                0x4A, 0x00              // Empty Dn
        } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteRequest> container = new LdapMessageContainer<>( codec );

        // Decode a DelRequest PDU
        Asn1Decoder.decode( stream, container );
    }


    /**
     * Test the decoding of a full DelRequest with controls
     */
    @Test
    public void testDecodeDelRequestSuccessWithControls() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x44 );

        stream.put( new byte[]
            {
              0x30, 0x42,               // LDAPMessage ::= SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                                        // CHOICE { ..., delRequest DelRequest, ...
                                        // DelRequest ::= [APPLICATION 10] LDAPDN;
                0x4A, 0x20,
                  'c', 'n', '=', 't', 'e', 's', 't', 'M', 'o', 'd', 'i', 'f', 'y', ',',
                  'o', 'u', '=', 'u', 's', 'e', 'r', 's', ',', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm',
                ( byte ) 0xA0, 0x1B,    // A control
                  0x30, 0x19,
                    0x04, 0x17,
                      '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.', '1', '1', '3',
                      '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<DeleteRequest> container = new LdapMessageContainer<>( codec );

        // Decode a DelRequest PDU
        Asn1Decoder.decode( stream, container );

        // Check the decoded DelRequest PDU
        DeleteRequest delRequest = container.getMessage();

        assertEquals( 1, delRequest.getMessageId() );
        assertEquals( "cn=testModify,ou=users,ou=system", delRequest.getName().toString() );

        // Check the Control
        Map<String, Control> controls = delRequest.getControls();

        assertEquals( 1, controls.size() );

        Control control = controls.get( "2.16.840.1.113730.3.4.2" );
        assertTrue( control instanceof ManageDsaIT );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessage( buffer, codec, delRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }
}
