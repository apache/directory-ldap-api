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
package org.apache.directory.api.ldap.codec.controls.proxiedauthz;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the ProxiedAuthzControlTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ProxiedAuthzControlTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a ProxiedAuthzControl with a DN user
     */
    @Test
    public void testDecodeProxiedAuthzControlDnSuccess() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm'
            } );
        bb.flip();
        
        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        assertEquals( "dn:dc=example,dc=com", control.getAuthzId() );

        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a normal user
     */
    @Test
    public void testDecodeProxiedAuthzControlUSuccess() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= u:elecharny
                'u', ':', 'e', 'l', (byte)0xc3, (byte)0xa9, 'c', 'h', 'a', 'r', 'n', 'y'
            } );
        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        assertEquals( "u:el\u00e9charny", control.getAuthzId() );

        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a anonymous user
     */
    @Test
    public void testDecodeProxiedAuthzControlAnonymousSuccess() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x00 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= anonymous
            } );
        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        assertEquals( "", control.getAuthzId() );

        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a wrong DN user
     */
    @Test
    public void testDecodeProxiedAuthzControlWrongDn() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c'
            } );
        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( control, bb.array() );
        } );
    }


    /**
     * Test the decoding of a ProxiedAuthzControl with a wrong user
     */
    @Test
    public void testDecodeProxiedAuthzControlWrongAuthzId() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                'v', 'n', ':', 'w', 'r', 'o', 'n', 'g'
            } );
        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.decodeValue( control, bb.array() );
        } );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedDnAuthzControl() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= dn:dc=example,dc=com
                  'd', 'n', ':', 'd', 'c', '=', 'e', 'x', 'a', 'm', 'p', 'l', 'e', ',', 'd', 'c', '=', 'c', 'o', 'm'
            } );

        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedUserAuthzControl() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x0C );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= u:elecharny
                'u', ':', 'e', 'l', (byte)0xc3, (byte)0xa9, 'c', 'h', 'a', 'r', 'n', 'y'
            } );

        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );

        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();
        
        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }


    /**
     * Test encoding of a ProxiedAuthzControl.
     */
    @Test
    public void testEncodeProxiedAnonymousAuthzControl() throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x00 );
        bb.put( new byte[]
            {
                // ProxiedAuthzNotification ::= anonymous
            } );

        bb.flip();

        ProxiedAuthzFactory factory = ( ProxiedAuthzFactory ) codec.getRequestControlFactories().
            get( ProxiedAuthz.OID );
        ProxiedAuthz control = factory.newControl();
        factory.decodeValue( control, bb.array() );


        // test reverse encoding
        Asn1Buffer buffer = new Asn1Buffer();

        factory.encodeValue( buffer, control );

        assertArrayEquals( bb.array(), buffer.getBytes().array() );
    }
}
