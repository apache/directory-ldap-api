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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyResponseDecorator;
import org.apache.directory.api.util.Strings;
import org.junit.Test;


/**
 * PasswordPolicyResponseControlTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyTest extends AbstractCodecServiceTest
{
    @Test
    public void testDecodeRespWithExpiryWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0xA );

        bb.put( new byte[]
            {
                0x30, 0x08,
                  ( byte ) 0xA0, 0x03,              // timeBeforeExpiration
                  ( byte ) 0x80, 0x01, 0x01,
                  ( byte ) 0x81, 0x01, 0x01         // ppolicyError
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertEquals( 1, passwordPolicy.getTimeBeforeExpiration() );
        assertEquals( 1, passwordPolicy.getPasswordPolicyError().getValue() );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeRespWithGraceAuthWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0xA );

        bb.put( new byte[]
            {
                0x30, 0x08,
                  ( byte ) 0xA0, 0x03,            // warning
                  ( byte ) 0x81, 0x01, 0x01,      // graceAuthNsRemaining
                  ( byte ) 0x81, 0x01, 0x01       // error
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertEquals( 1, passwordPolicy.getGraceAuthNRemaining() );
        assertEquals( 1, passwordPolicy.getPasswordPolicyError().getValue() );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeRespWithTimeBeforeExpiryWarningOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 7 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  ( byte ) 0xA0, 0x03,
                  ( byte ) 0x80, 0x01, 0x01 //  timeBeforeExpiration
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertEquals( 1, passwordPolicy.getTimeBeforeExpiration() );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeRespWithGraceAuthWarningOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 7 );

        bb.put( new byte[]
            {
                0x30, 0x05,
                  ( byte ) 0xA0, 0x03,
                  ( byte ) 0x81, 0x01, 0x01 //  graceAuthNsRemaining
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertEquals( 1, passwordPolicy.getGraceAuthNRemaining() );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeRespWithErrorOnly() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 5 );

        bb.put( new byte[]
            {
                0x30, 0x03,
                  ( byte ) 0x81, 0x01, 0x01 //  error
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertEquals( 1, passwordPolicy.getPasswordPolicyError().getValue() );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }


    @Test
    public void testDecodeRespWithoutWarningAndError() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 2 );

        bb.put( new byte[]
            {
                0x30, 0x00
        } );

        bb.flip();

        PasswordPolicyResponseDecorator control = new PasswordPolicyResponseDecorator( codec );
        PasswordPolicyResponse passwordPolicy = ( PasswordPolicyResponse ) control.decode( bb.array() );

        assertNotNull( passwordPolicy );

        ByteBuffer encoded = ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).encode(
            ByteBuffer.allocate( ( ( PasswordPolicyResponseDecorator ) passwordPolicy ).computeLength() ) );
        assertEquals( Strings.dumpBytes( bb.array() ), Strings.dumpBytes( encoded.array() ) );
    }
}
