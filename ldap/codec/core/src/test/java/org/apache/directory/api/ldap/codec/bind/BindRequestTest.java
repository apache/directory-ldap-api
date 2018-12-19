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
package org.apache.directory.api.ldap.codec.bind;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractMessageDecorator;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.codec.decorators.BindRequestDecorator;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponseImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
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
public class BindRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a BindRequest with Simple authentication and no
     * controls
     */
    /* Not used in unit tests
    @Test
    public void testDecodeBindRequestSimpleNoControlsPerf()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x52 );
        stream.put( new byte[]
             {
             0x30, 0x50,                 // LDAPMessage ::=SEQUENCE {
               0x02, 0x01, 0x01,         // messageID MessageID
               0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                         // BindRequest ::= APPLICATION[0] SEQUENCE {
                 0x02, 0x01, 0x03,       // version INTEGER (1..127),
                 0x04, 0x1F,             // name LDAPDN,
                 'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',', 'd', 'c', '=', 'e', 'x', 'a',
                 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                 ( byte ) 0x80, 0x08,    // authentication AuthenticationChoice
                                         // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                         // ...
                   'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
               ( byte ) 0xA0, 0x1B, // A control
                 0x30, 0x19,
                   0x04, 0x17,
                     0x32, 0x2E, 0x31, 0x36, 0x2E, 0x38, 0x34, 0x30, 0x2E, 0x31, 0x2E, 0x31, 0x31, 0x33, 0x37, 0x33,
                     0x30, 0x2E, 0x33, 0x2E, 0x34, 0x2E, 0x32
             } );

        String decodedPdu = StringTools.dumpBytes( stream.array() );
        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container container = new LdapMessageContainer();

        // Decode the BindRequest PDU
        try
        {
            long t0 = System.currentTimeMillis();
            for ( int i = 0; i < 10000; i++ )
            {
                ldapDecoder.decode( stream, container );
                container).clean();
                stream.flip();
            }
            long t1 = System.currentTimeMillis();
            System.out.println( "Delta = " + ( t1 - t0 ) );

            ldapDecoder.decode( stream, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        // Check the decoded BindRequest
        LdapMessage message = container.getLdapMessage();
        BindRequest br = message.getMessage();

        assertEquals( 1, message.getMessageId() );
        assertEquals( 3, br.getVersion() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", br.getName().toString() );
        assertEquals( true, ( br.getAuthentication() instanceof SimpleAuthentication ) );
        assertEquals( "password", StringTools.utf8ToString( ( ( SimpleAuthentication ) br.getAuthentication() )
            .getSimple() ) );

        // Check the Control
        List controls = message.getControls();

        assertEquals( 1, controls.size() );

        Control control = message.getControls( 0 );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertEquals( "", StringTools.dumpBytes( ( byte[] ) control.getValue() ) );

        // Check the length
        assertEquals( 0x52, message.computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb = message.encode();

            String encodedPdu = StringTools.dumpBytes( bb.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }
    */

    /**
     * Test the decoding of a BindRequest with Simple authentication and
     * controls
     */
    @Test
    public void testDecodeBindRequestSimpleWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with Simple authentication and
     * controls
     */
    @Test
    public void testDecodeBindRequestBadDN() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x35 );
        stream.put( new byte[]
            {
                0x30, 0x33,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x2E,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', ':', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0x80, 0x08,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        try
        {
            ldapDecoder.decode( stream, container );

            BindRequest bindRequest = container.getMessage();
            assertNull( bindRequest.getDn() );
            assertEquals( "uid:akarasulu,dc=example,dc=com", bindRequest.getName() );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof BindResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_DN_SYNTAX, ( ( BindResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }
    }


    /**
     * Test the decoding of a BindRequest with Simple authentication, no name
     * and no controls
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestSimpleNoName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x15 );
        stream.put( new byte[]
            {
                0x30, 0x13,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x0D,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    ( byte ) 0x80, 0x08,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container container = new LdapMessageContainer<AbstractMessageDecorator<? extends Message>>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with Simple authentication, empty name
     * (an anonymous bind) and no controls
     */
    @Test
    public void testDecodeBindRequestSimpleEmptyName() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x16 );
        stream.put( new byte[]
            {
                0x30, 0x14,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x0F,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x00,             // name LDAPDN,
                    ( byte ) 0x80, 0x08,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { simple [0] OCTET STRING,
                                            // ...
                      'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "password", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with Sasl authentication, no
     * credentials and no controls
     */
    @Test
    public void testDecodeBindRequestSaslNoCredsNoControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x3A );
        stream.put( new byte[]
            {
                0x30, 0x38,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x33,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0xA3, 0x0D,    // authentication AuthenticationChoice
                                            // AuthenticationChoice ::= CHOICE { ... sasl [3]
                                            // SaslCredentials }
                                            // SaslCredentials ::= SEQUENCE {
                                            // mechanism LDAPSTRING,
                                            // ...
                      0x04, 0x0B,
                        'K', 'E', 'R', 'B', 'E', 'R', 'O', 'S', '_', 'V', '4'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName().toString() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "KERBEROS_V4", bindRequest.getSaslMechanism() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with Sasl authentication, a
     * credentials and no controls
     */
    @Test
    public void testDecodeBindRequestSaslCredsNoControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x42 );
        stream.put( new byte[]
            {
                0x30, 0x40,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x3B,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x1F,             // name LDAPDN,
                      'u', 'i', 'd', '=', 'a', 'k', 'a', 'r', 'a', 's', 'u', 'l', 'u', ',',
                      'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm',
                    ( byte ) 0xA3, 0x15,    // authentication AuthenticationChoice
                                            // }
                                            // AuthenticationChoice ::= CHOICE { ... sasl [3]
                                            // SaslCredentials }
                                            // SaslCredentials ::= SEQUENCE {
                                            // mechanism LDAPSTRING,
                                            // ...
                      0x04, 0x0B,
                        'K', 'E', 'R', 'B', 'E', 'R', 'O', 'S', '_', 'V', '4',
                      ( byte ) 0x04, 0x06,  // SaslCredentials ::= SEQUENCE {
                                            // ...
                                            // credentials OCTET STRING OPTIONAL }
                                            //
                        'a', 'b', 'c', 'd', 'e', 'f'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "uid=akarasulu,dc=example,dc=com", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "KERBEROS_V4", bindRequest.getSaslMechanism() );
        assertEquals( "abcdef", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with Sasl authentication, no name, a
     * credentials and no controls
     */
    @Test
    public void testDecodeBindRequestSaslNoNameCredsNoControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x23 );
        stream.put( new byte[]
            {
                0x30, 0x21,                 // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                  0x60, 0x1C,               // CHOICE { ..., bindRequest BindRequest, ...
                                            // BindRequest ::= APPLICATION[0] SEQUENCE {
                    0x02, 0x01, 0x03,       // version INTEGER (1..127),
                    0x04, 0x00,             // name LDAPDN,
                    ( byte ) 0xA3, 0x15,    // authentication AuthenticationChoice
                                            // }
                                            // AuthenticationChoice ::= CHOICE { ... sasl [3]
                                            // SaslCredentials }
                                            // SaslCredentials ::= SEQUENCE {
                                            // mechanism LDAPSTRING,
                                            // ...
                      0x04, 0x0B,
                        'K', 'E', 'R', 'B', 'E', 'R', 'O', 'S', '_', 'V', '4',
                      ( byte ) 0x04, 0x06,  // SaslCredentials ::= SEQUENCE {
                                            // ...
                                            // credentials OCTET STRING OPTIONAL }
                                            //
                        'a', 'b', 'c', 'd', 'e', 'f'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "KERBEROS_V4", bindRequest.getSaslMechanism() );
        assertEquals( "abcdef", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with an empty body
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestEmptyBody() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );
        stream.put( new byte[]
            {
                0x30, 0x05,         // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01, // messageID MessageID
                  0x60, 0x00        // CHOICE { ..., bindRequest BindRequest, ...
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with an empty version
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestEmptyVersion() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x09 );
        stream.put( new byte[]
            {
                0x30, 0x07,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x02,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x00          // version INTEGER (1..127),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with a bad version (0)
     */
    @Test( expected= DecoderException.class )
    public void testDecodeBindRequestBadVersion0() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0A );
        stream.put( new byte[]
            {
                0x30, 0x08,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x03,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x00    // version INTEGER (1..127),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with a bad version (4)
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestBadVersion4() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0A );
        stream.put( new byte[]
            {
                0x30, 0x08,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x03,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x04    // version INTEGER (1..127),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with a bad version (128)
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestBadVersion128() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0C );
        stream.put( new byte[]
            {
                0x30, 0x0A,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x04,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x02, 0x00, ( byte ) 0x80 // version INTEGER (1..127),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with no name
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestNoName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0A );
        stream.put( new byte[]
            {
                0x30, 0x08,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x03,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03    // version INTEGER (1..127),
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with an empty name
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestEmptyName() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0C );
        stream.put( new byte[]
            {
                0x30, 0x0A,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x05,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        ldapDecoder.decode( stream, container );
    }


    /**
     * Test the decoding of a BindRequest with an empty simple
     */
    @Test
    public void testDecodeBindRequestEmptySimple() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );
        stream.put( new byte[]
            {
                0x30, 0x0C,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x07,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0x80, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertTrue( bindRequest.isSimple() );
        assertEquals( "", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with an empty sasl
     */
    @Test( expected=DecoderException.class )
    public void testDecodeBindRequestEmptySasl() throws DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );
        stream.put( new byte[]
            {
                0x30, 0x0C,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x07,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode a BindRequest message
        try
        {
            ldapDecoder.decode( stream, container );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ( ( ResponseCarryingException ) de ).getResponse();
            assertTrue( response instanceof BindResponseImpl );
            assertEquals( ResultCodeEnum.INVALID_CREDENTIALS, ( ( BindResponseImpl ) response ).getLdapResult()
                .getResultCode() );

            throw de;
        }

        fail( "We should not reach this point" );
    }


    /**
     * Test the decoding of a BindRequest with an empty mechanism
     */
    @Test
    public void testDecodeBindRequestEmptyMechanism() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x10 );
        stream.put( new byte[]
            {
                0x30, 0x0E,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x09,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x02,
                      0x04, 0x00
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "", bindRequest.getSaslMechanism() );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with an bad mechanism
     */
    /* This test is not valid. I don't know how to generate a UnsupportedEncodingException ...
    @Test
    public void testDecodeBindRequestBadMechanism()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x11 );
        stream.put( new byte[]
            {
            0x30, 0x0F,                 // LDAPMessage ::=SEQUENCE {
              0x02, 0x01, 0x01,         // messageID MessageID
              0x60, 0x0A,               // CHOICE { ..., bindRequest BindRequest, ...
                0x02, 0x01, 0x03,       // version INTEGER (1..127),
                0x04, 0x00,
                ( byte ) 0xA3, 0x03,
                  0x04, 0x01, (byte)0xFF
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        Asn1Container container = new LdapMessageContainer();

        // Decode the BindRequest PDU
        try
        {
            ldapDecoder.decode( stream, container );
        }
        catch ( DecoderException de )
        {
            assertTrue( de instanceof ResponseCarryingException );
            Message response = ((ResponseCarryingException)de).getResponse();
            assertTrue( response instanceof BindResponseImpl );
            assertEquals( ResultCodeEnum.INAPPROPRIATEAUTHENTICATION, ((BindResponseImpl)response).getLdapResult().getResultCode() );
            return;
        }

        fail( "We should not reach this point" );
    }
    */

    /**
     * Test the decoding of a BindRequest with an empty credentials
     */
    @Test
    public void testDecodeBindRequestEmptyCredentials() throws EncoderException, DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x12 );
        stream.put( new byte[]
            {
                0x30, 0x10,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x0B,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x04,
                      0x04, 0x00,
                      0x04, 0x00,
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "", bindRequest.getSaslMechanism() );
        assertEquals( "", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );

        assertArrayEquals(
            new byte[]
                {
                    0x30, 0x0E,             // LDAPMessage ::=SEQUENCE {
                      0x02, 0x01, 0x01,     // messageID MessageID
                      0x60, 0x09,           // CHOICE { ..., bindRequest BindRequest, ...
                        0x02, 0x01, 0x03,   // version INTEGER (1..127),
                        0x04, 0x00,
                        ( byte ) 0xA3, 0x02,
                          0x04, 0x00
                },
            buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with an empty credentials with
     * controls
     */
    @Test
    public void testDecodeBindRequestEmptyCredentialsWithControls() throws DecoderException, EncoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x2F );
        stream.put( new byte[]
            {
                0x30, 0x2D,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x0B,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x04,
                      0x04, 0x00,
                      0x04, 0x00,
                  ( byte ) 0xA0, 0x1B,  // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "", bindRequest.getSaslMechanism() );
        assertEquals( "", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check the Control
        Map<String, Control> controls = bindRequest.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( CodecControl<Control> ) controls
            .get( "2.16.840.1.113730.3.4.2" );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );
        assertArrayEquals( 
            new byte[]
            {
                0x30, 0x2B,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x09,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x02,
                      0x04, 0x00,
                  ( byte ) 0xA0, 0x1B,  // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            }, buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a BindRequest with an empty mechanisms with controls
     */
    @Test
    public void testDecodeBindRequestEmptyMechanismWithControls() throws EncoderException, DecoderException
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x2D );
        stream.put( new byte[]
            {
                0x30, 0x2B,             // LDAPMessage ::=SEQUENCE {
                  0x02, 0x01, 0x01,     // messageID MessageID
                  0x60, 0x09,           // CHOICE { ..., bindRequest BindRequest, ...
                    0x02, 0x01, 0x03,   // version INTEGER (1..127),
                    0x04, 0x00,
                    ( byte ) 0xA3, 0x02,
                      0x04, 0x00,
                  ( byte ) 0xA0, 0x1B,  // A control
                    0x30, 0x19,
                      0x04, 0x17,
                        '2', '.', '1', '6', '.', '8', '4', '0', '.', '1', '.',
                        '1', '1', '3', '7', '3', '0', '.', '3', '.', '4', '.', '2'
            } );

        stream.flip();

        // Allocate a LdapMessage Container
        LdapMessageContainer<BindRequestDecorator> container = new LdapMessageContainer<>( codec );

        // Decode the BindRequest PDU
        ldapDecoder.decode( stream, container );

        // Check the decoded BindRequest
        BindRequest bindRequest = container.getMessage();

        assertEquals( 1, bindRequest.getMessageId() );
        assertTrue( bindRequest.isVersion3() );
        assertEquals( "", bindRequest.getName() );
        assertFalse( bindRequest.isSimple() );
        assertEquals( "", bindRequest.getSaslMechanism() );
        assertEquals( "", Strings.utf8ToString( bindRequest.getCredentials() ) );

        // Check the Control
        Map<String, Control> controls = bindRequest.getControls();

        assertEquals( 1, controls.size() );

        @SuppressWarnings("unchecked")
        CodecControl<Control> control = ( org.apache.directory.api.ldap.codec.api.CodecControl<Control> ) controls
            .get( "2.16.840.1.113730.3.4.2" );
        assertEquals( "2.16.840.1.113730.3.4.2", control.getOid() );
        assertEquals( "", Strings.dumpBytes( control.getValue() ) );

        // Check encode reverse
        Asn1Buffer buffer = new Asn1Buffer();

        LdapEncoder.encodeMessageReverse( buffer, codec, bindRequest );
        assertArrayEquals( stream.array(), buffer.getBytes().array() );
    }

    /**
     * Test the decoding of a BindRequest with Simple authentication and no
     * controls
     */
    /* No used by unit tests
    @Test
    public void testPerf() throws Exception
    {
        Dn name = new Dn( "uid=akarasulu,dc=example,dc=com" );
        long t0 = System.currentTimeMillis();

        for ( int i = 0; i< 10000; i++)
        {
            // Check the decoded BindRequest
            LdapMessage message = new LdapMessage();
            message.setMessageId( 1 );

            BindRequest br = new BindRequest();
            br.setMessageId( 1 );
            br.setName( name );

            Control control = new Control();
            control.setControlType( "2.16.840.1.113730.3.4.2" );

            LdapAuthentication authentication = new SimpleAuthentication();
            ((SimpleAuthentication)authentication).setSimple( StringTools.getBytesUtf8( "password" ) );

            br.addControl( control );
            br.setAuthentication( authentication );
            message.setProtocolOP( br );

            // Check the encoding
            try
            {
                message.encode();
            }
            catch ( EncoderException ee )
            {
                ee.printStackTrace();
                fail( ee.getMessage() );
            }
        }

        long t1 = System.currentTimeMillis();
        System.out.println( "Delta = " + (t1 - t0));
    }
    */
}
