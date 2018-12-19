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
package org.apache.directory.api.ldap.codec.unbind;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.UnbindRequestDecorator;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.UnbindRequest;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class UnBindRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a UnBindRequest with no controls
     */
    @Test
    public void testDecodeUnBindRequestNoControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );
        stream.put( new byte[]
            {
              0x30, 0x05,               // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                0x42, 0x00,             // CHOICE { ..., unbindRequest UnbindRequest,...
                                        // UnbindRequest ::= [APPLICATION 2] NULL
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<UnbindRequestDecorator> ldapMessageContainer = new LdapMessageContainer<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        UnbindRequest unbindRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, unbindRequest.getMessageId() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, unbindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a UnBindRequest with controls
     */
    @Test
    public void testDecodeUnBindRequestWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x24 );
        stream.put( new byte[]
            {
              0x30, 0x22,               // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                0x42, 0x00,             // CHOICE { ..., unbindRequest UnbindRequest,...
                                        // UnbindRequest ::= [APPLICATION 2] NULL
                ( byte ) 0xA0, 0x1B,    // A control
                  0x30, 0x19,
                    0x04, 0x17,
                      '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                      '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a BindRequest Container
        LdapMessageContainer<UnbindRequestDecorator> ldapMessageContainer = new LdapMessageContainer<>( codec );

        ldapDecoder.decode( stream, ldapMessageContainer );

        UnbindRequest unbindRequest = ldapMessageContainer.getMessage();

        assertEquals( 1, unbindRequest.getMessageId() );

        // Check the Control
        Map<String, Control> controls = unbindRequest.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( CodecControl<Control> ) controls
            .get( "2.16.840.1.113730.3.4.2" );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, unbindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a UnBindRequest with a not null body
     */
    @Test( expected=DecoderException.class )
    public void testDecodeUnBindRequestNotNull() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x09 );
        stream.put( new byte[]
            {
              0x30, 0x07,               // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x01,       // messageID MessageID
                0x42, 0x02,             // CHOICE { ..., unbindRequest UnbindRequest,...
                  0x04, 0x00            // UnbindRequest ::= [APPLICATION 2] NULL
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<UnbindRequestDecorator> ldapMessageContainer = new LdapMessageContainer<>( codec );

        // Decode a UnbindRequest message
        ldapDecoder.decode( stream, ldapMessageContainer );
    }
}
