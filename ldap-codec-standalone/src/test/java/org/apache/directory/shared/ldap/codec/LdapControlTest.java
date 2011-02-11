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
package org.apache.directory.shared.ldap.codec;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;
import java.util.Map;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;
import org.apache.directory.shared.asn1.ber.Asn1Decoder;
import org.apache.directory.shared.asn1.ber.Asn1Container;
import org.apache.directory.shared.asn1.DecoderException;
import org.apache.directory.shared.asn1.EncoderException;
import org.apache.directory.shared.ldap.codec.api.CodecControl;
import org.apache.directory.shared.ldap.codec.decorators.AbandonRequestDecorator;
import org.apache.directory.shared.ldap.codec.decorators.MessageDecorator;
import org.apache.directory.shared.ldap.model.message.AbandonRequest;
import org.apache.directory.shared.ldap.model.message.AbandonRequestImpl;
import org.apache.directory.shared.ldap.model.message.Control;
import org.apache.directory.shared.ldap.model.message.Message;
import org.apache.directory.shared.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;


@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class LdapControlTest extends AbstractCodecServiceTest
{
    
    /**
     * Test the decoding of a Request with controls
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testDecodeRequestWithControls()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x64 );
        stream.put( new byte[]
            { 0x30, 0x62, // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x03, // messageID MessageID
                0x50, 0x01, 0x02, // CHOICE { ..., abandonRequest
                // AbandonRequest,...
                ( byte ) 0xA0, 0x5A, // controls [0] Controls OPTIONAL }
                0x30, 0x1A, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x0D, '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '1',
                // criticality BOOLEAN DEFAULT FALSE,
                0x01, 0x01, ( byte ) 0xFF,
                // controlValue OCTET STRING OPTIONAL }
                0x04, 0x06, 'a', 'b', 'c', 'd', 'e', 'f', 0x30, 0x17, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x0D, '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '2',
                // controlValue OCTET STRING OPTIONAL }
                0x04, 0x06, 'g', 'h', 'i', 'j', 'k', 'l', 0x30, 0x12, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x0D, '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '3',
                // criticality BOOLEAN DEFAULT FALSE}
                0x01, 0x01, ( byte ) 0xFF, 0x30, 0x0F, // Control ::= SEQUENCE {
                // controlType LDAPOID}
                0x04, 0x0D, '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '4' } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        LdapMessageContainer<AbandonRequestDecorator> ldapMessageContainer = 
            new LdapMessageContainer<AbandonRequestDecorator>( codec );

        // Decode the PDU
        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        // Check that everything is OK
        AbandonRequestDecorator abandonRequest = ldapMessageContainer.getMessage();

        // Copy the message
        AbandonRequest internalAbandonRequest = new AbandonRequestImpl( abandonRequest.getMessageId() );
        internalAbandonRequest.setAbandoned( abandonRequest.getAbandoned() );

        assertEquals( 3, abandonRequest.getMessageId() );
        assertEquals( 2, abandonRequest.getAbandoned() );

        // Check the Controls
        Map<String, Control> controls = abandonRequest.getControls();

        assertEquals( 4, controls.size() );

        CodecControl<Control> control = (org.apache.directory.shared.ldap.codec.api.CodecControl<Control> ) controls.get( "1.3.6.1.5.5.1" );
        assertEquals( "1.3.6.1.5.5.1", control.getOid() );
        assertEquals( "0x61 0x62 0x63 0x64 0x65 0x66 ", Strings.dumpBytes( ( byte[] ) control.getValue() ) );
        assertTrue( control.isCritical() );
        internalAbandonRequest.addControl( control );

        control = (org.apache.directory.shared.ldap.codec.api.CodecControl<Control> ) controls.get( "1.3.6.1.5.5.2" );
        assertEquals( "1.3.6.1.5.5.2", control.getOid() );
        assertEquals( "0x67 0x68 0x69 0x6A 0x6B 0x6C ", Strings.dumpBytes((byte[]) control.getValue()) );
        assertFalse( control.isCritical() );
        internalAbandonRequest.addControl( control );

        control = (org.apache.directory.shared.ldap.codec.api.CodecControl<Control> ) controls.get( "1.3.6.1.5.5.3" );
        assertEquals( "1.3.6.1.5.5.3", control.getOid() );
        assertEquals( "", Strings.dumpBytes((byte[]) control.getValue()) );
        assertTrue( control.isCritical() );
        internalAbandonRequest.addControl( control );

        control = (org.apache.directory.shared.ldap.codec.api.CodecControl<Control> ) controls.get( "1.3.6.1.5.5.4" );
        assertEquals( "1.3.6.1.5.5.4", control.getOid() );
        assertEquals( "", Strings.dumpBytes((byte[]) control.getValue()) );
        assertFalse( control.isCritical() );
        internalAbandonRequest.addControl( control );

        // Check the encoding
        try
        {
            ByteBuffer bb = encoder.encodeMessage( internalAbandonRequest );

            // Check the length
            assertEquals( 0x64, bb.limit() );

            // Don't check the PDU, as control are in a Map, and can be in a different order
            // So we decode the generated PDU, and we compare it with the initial message
            try
            {
                ldapDecoder.decode( bb, ldapMessageContainer );
            }
            catch ( DecoderException de )
            {
                de.printStackTrace();
                fail( de.getMessage() );
            }

            AbandonRequest abandonRequest2 = ldapMessageContainer.getMessage();

            assertEquals( abandonRequest, abandonRequest2 );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a Request with null OID controls
     */
    @Test
    public void testDecodeRequestWithControlsNullOID()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x19 );
        stream.put( new byte[]
            { 0x30, 0x17, // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x03, // messageID MessageID
                0x50, 0x01, 0x02, // CHOICE { ..., abandonRequest
                // AbandonRequest,...
                ( byte ) 0xA0, 0x0F, // controls [0] Controls OPTIONAL }
                0x30, 0x0D, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x00,
                // criticality BOOLEAN DEFAULT FALSE,
                0x01, 0x01, ( byte ) 0xFF,
                // controlValue OCTET STRING OPTIONAL }
                0x04, 0x06, 'a', 'b', 'c', 'd', 'e', 'f', } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        Asn1Container ldapMessageContainer = 
            new LdapMessageContainer<MessageDecorator<? extends Message>>( codec );

        // Decode the PDU
        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
            return;
        }

        fail( "We should not reach this point" );
    }


    /**
     * Test the decoding of a Request with bad OID controls
     */
    @Test
    public void testDecodeRequestWithControlsBadOID()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x20 );
        stream.put( new byte[]
            { 0x30, 0x1E, // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x03, // messageID MessageID
                0x50, 0x01, 0x02, // CHOICE { ..., abandonRequest
                // AbandonRequest,...
                ( byte ) 0xA0, 0x16, // controls [0] Controls OPTIONAL }
                0x30, 0x14, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x07, 'b', 'a', 'd', ' ', 'o', 'i', 'd',
                // criticality BOOLEAN DEFAULT FALSE,
                0x01, 0x01, ( byte ) 0xFF,
                // controlValue OCTET STRING OPTIONAL }
                0x04, 0x06, 'a', 'b', 'c', 'd', 'e', 'f', } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        Asn1Container ldapMessageContainer = 
            new LdapMessageContainer<MessageDecorator<? extends Message>>( codec );

        // Decode the PDU
        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
            return;
        }

        fail( "We should not reach this point" );
    }


    /**
     * Test the decoding of a Request with bad criticality
     */
    @Test
    public void testDecodeRequestWithControlsBadCriticality()
    {
        Asn1Decoder ldapDecoder = new Asn1Decoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x25 );
        stream.put( new byte[]
            { 0x30, 0x23, // LDAPMessage ::=SEQUENCE {
                0x02, 0x01, 0x03, // messageID MessageID
                0x50, 0x01, 0x02, // CHOICE { ..., abandonRequest
                // AbandonRequest,...
                ( byte ) 0xA0, 0x1B, // controls [0] Controls OPTIONAL }
                0x30, 0x19, // Control ::= SEQUENCE {
                // controlType LDAPOID,
                0x04, 0x0D, '1', '.', '3', '.', '6', '.', '1', '.', '5', '.', '5', '.', '1',
                // criticality BOOLEAN DEFAULT FALSE,
                0x01, 0x00,
                // controlValue OCTET STRING OPTIONAL }
                0x04, 0x06, 'a', 'b', 'c', 'd', 'e', 'f', } );

        stream.flip();

        // Allocate a LdapMessageContainer Container
        Asn1Container ldapMessageContainer = 
            new LdapMessageContainer<MessageDecorator<? extends Message>>( codec );

        // Decode the PDU
        try
        {
            ldapDecoder.decode( stream, ldapMessageContainer );
        }
        catch ( DecoderException de )
        {
            assertTrue( true );
            return;
        }

        fail( "We should not reach this point" );
    }
}
