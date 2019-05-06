/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.extras.controls.ppolicy;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyResponseFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * PasswordPolicyResponseControlTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class PasswordPolicyResponseTest extends AbstractCodecServiceTest
{
    @BeforeEach
    public void init()
    {
        codec.registerResponseControl( new PasswordPolicyResponseFactory( codec ) );
    }

    
    @Test
    public void testDecodeRespWithExpiryWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0xA );

        bb.put( new byte[]
            {
                0x30, 0x08,                         // PasswordPolicyResponseValue ::= SEQUENCE {
                  ( byte ) 0xA0, 0x03,              //     warning [0] CHOICE {
                    ( byte ) 0x80, 0x01, 0x01,      //        timeBeforeExpiration [0] INTEGER (0 .. maxInt),
                  ( byte ) 0x81, 0x01, 0x01         //     error   [1] ENUMERATED {
                                                    //          accountLocked               (1),
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );


        assertEquals( 1, passwordPolicyResponse.getTimeBeforeExpiration() );
        assertEquals( 1, passwordPolicyResponse.getPasswordPolicyError().getValue() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );

    }


    @Test
    public void testDecodeRespWithGraceAuthWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0xA );

        bb.put( new byte[]
            {
                0x30, 0x08,                         // PasswordPolicyResponseValue ::= SEQUENCE {
                  ( byte ) 0xA0, 0x03,              //     warning [0] CHOICE {
                    ( byte ) 0x81, 0x01, 0x01,      //         graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
                  ( byte ) 0x81, 0x01, 0x01         //     error   [1] ENUMERATED {
                                                    //          accountLocked               (1),
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );

        assertEquals( 1, passwordPolicyResponse.getGraceAuthNRemaining() );
        assertEquals( 1, passwordPolicyResponse.getPasswordPolicyError().getValue() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeRespWithTimeBeforeExpiryWarningOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 7 );

        bb.put( new byte[]
            {
                0x30, 0x05,                     // PasswordPolicyResponseValue ::= SEQUENCE {
                  ( byte ) 0xA0, 0x03,          //     warning [0] CHOICE {
                    ( byte ) 0x80, 0x01, 0x01   //        timeBeforeExpiration [0] INTEGER (0 .. maxInt),
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );

        assertEquals( 1, passwordPolicyResponse.getTimeBeforeExpiration() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeRespWithGraceAuthWarningOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 7 );

        bb.put( new byte[]
            {
                0x30, 0x05,                     // PasswordPolicyResponseValue ::= SEQUENCE {
                  ( byte ) 0xA0, 0x03,          //     warning [0] CHOICE {
                    ( byte ) 0x81, 0x01, 0x01   //         graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );

        assertEquals( 1, passwordPolicyResponse.getGraceAuthNRemaining() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeRespWithErrorOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 5 );

        bb.put( new byte[]
            {
                0x30, 0x03,                     // PasswordPolicyResponseValue ::= SEQUENCE {
                  ( byte ) 0x81, 0x01, 0x01     //     error   [1] ENUMERATED {
                                                //          accountLocked               (1),
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );

        assertEquals( 1, passwordPolicyResponse.getPasswordPolicyError().getValue() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    @Test
    public void testDecodeRespWithoutWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 2 );

        bb.put( new byte[]
            {
                0x30, 0x00                      // PasswordPolicyResponseValue ::= SEQUENCE {
            } );

        bb.flip();

        PasswordPolicyResponseFactory factory = ( PasswordPolicyResponseFactory ) codec.getResponseControlFactories().
            get( PasswordPolicyResponse.OID );
        PasswordPolicyResponse passwordPolicyResponse = factory.newControl();
        factory.decodeValue( passwordPolicyResponse, bb.array() );

        assertNotNull( passwordPolicyResponse );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, passwordPolicyResponse );

        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }
}
