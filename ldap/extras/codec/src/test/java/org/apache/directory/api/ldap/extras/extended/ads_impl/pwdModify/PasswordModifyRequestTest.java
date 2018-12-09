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
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyRequestContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyRequestDecorator;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the PasswordModifyRequest codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class PasswordModifyRequestTest extends AbstractCodecServiceTest
{
    /**
     * Test the decoding of a PasswordModifyRequest with nothing in it
     */
    @Test
    public void testDecodePasswordModifyRequestEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            { 
                0x30, 0x00, // PasswordModifyRequest ::= SEQUENCE {
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x02, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityNull() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            { 
                0x30, 0x02,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x00       // userIdentity    [0]  OCTET STRING OPTIONAL
        } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( 0, pwdModifyRequest.getUserIdentity().length );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x04,  ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValue() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 
                0x30, 0x06,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd'
        } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x08, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * an empty newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPasswordEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 
                0x30, 0x08,                   // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,        // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x00         // newPassword    [2]  OCTET STRING OPTIONAL
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( 0, pwdModifyRequest.getNewPassword().length );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * a newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPassword() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 
                0x30, 0x0C,                     // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,          // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x04,          // newPassword    [2]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getNewPassword() ) );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 
                0x30, 0x08,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x00       // oldPassword    [1]  OCTET STRING OPTIONAL
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( 0, pwdModifyRequest.getOldPassword().length );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValue() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 
                0x30, 0x0C,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and empty newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordNull() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );
        bb.put( new byte[]
            { 
                0x30, 0x0E,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h',
                  ( byte ) 0x82, 0x00       // newPassword    [2]  OCTET STRING OPTIONAL
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( 0, pwdModifyRequest.getNewPassword().length );

        // Check the length
        assertEquals( 0x10, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and a newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordValue() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            { 
                0x30, 0x12,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x80, 0x04,      // userIdentity    [0]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h',
                  ( byte ) 0x82, 0x04,      // newPassword    [2]  OCTET STRING OPTIONAL
                    'i', 'j', 'k', 'l'
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( "ijkl", Strings.utf8ToString( pwdModifyRequest.getNewPassword() ) );

        // Check the length
        assertEquals( 0x14, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordNull() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            { 
                0x30, 0x02,             // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x00   // oldPassword    [1]  OCTET STRING OPTIONAL
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( 0, pwdModifyRequest.getOldPassword().length );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x04, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValue() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 
                0x30, 0x06,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd'
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x08, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * empty  newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordEmpty() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 
                0x30, 0x08,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x00       // newPassword    [2]  OCTET STRING OPTIONAL
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( 0, pwdModifyRequest.getNewPassword().length );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordValue() throws DecoderException
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 
                0x30, 0x0C,                 // PasswordModifyRequest ::= SEQUENCE {
                  ( byte ) 0x81, 0x04,      // oldPassword    [1]  OCTET STRING OPTIONAL
                    'a', 'b', 'c', 'd',
                  ( byte ) 0x82, 0x04,      // newPassword    [2]  OCTET STRING OPTIONAL
                    'e', 'f', 'g', 'h'
            } );

        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        decoder.decode( bb, container );

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getNewPassword() ) );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

        assertArrayEquals( bb.array(), bb1.array() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        PasswordModifyFactory factory = new PasswordModifyFactory( codec );
        factory.encodeValue( asn1Buffer, pwdModifyRequest );
        assertArrayEquals( bb.array(),  asn1Buffer.getBytes().array() );
    }
}
