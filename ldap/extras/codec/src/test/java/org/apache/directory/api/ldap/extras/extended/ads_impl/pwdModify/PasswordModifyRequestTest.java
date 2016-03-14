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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
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
public class PasswordModifyRequestTest
{
    /**
     * Test the decoding of a PasswordModifyRequest with nothing in it
     */
    @Test
    public void testDecodePasswordModifyRequestEmpty()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            { 0x30, 0x00, // PasswordModifyRequest ::= SEQUENCE {
            } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x02, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityNull()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            { 0x30, 0x02, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x00 // userIdentity    [0]  OCTET STRING OPTIONAL
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( 0, pwdModifyRequest.getUserIdentity().length );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x04,  ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 0x30, 0x06, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x08, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * an empty newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPasswordEmpty()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 0x30, 0x08, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x00
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( 0, pwdModifyRequest.getNewPassword().length );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity and
     * a newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueNewPassword()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 0x30, 0x0C, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x04,
                'e',
                'f',
                'g',
                'h'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNull( pwdModifyRequest.getOldPassword() );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getNewPassword() ) );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordEmpty()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 0x30, 0x08, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x81,
                0x00 // oldPassword    [1]  OCTET STRING OPTIONAL
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( 0, pwdModifyRequest.getOldPassword().length );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 0x30, 0x0C, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'e',
                'f',
                'g',
                'h'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNotNull( pwdModifyRequest.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getUserIdentity() ) );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and empty newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordNull()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x10 );
        bb.put( new byte[]
            { 0x30, 0x0E, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'e',
                'f',
                'g',
                'h',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x00
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

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
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with a user identity, and oldPassword and
     * and a newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestUserIdentityValueOldPasswordValueNewPasswordValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x14 );
        bb.put( new byte[]
            { 0x30, 0x12, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // userIdentity    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'e',
                'f',
                'g',
                'h',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x04,
                'i',
                'j',
                'k',
                'l'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

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
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an empty user identity
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordNull()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            { 0x30, 0x02, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x81,
                0x00 // oldPassword    [1]  OCTET STRING OPTIONAL
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( 0, pwdModifyRequest.getOldPassword().length );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x04, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 0x30, 0x06, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNull( pwdModifyRequest.getNewPassword() );

        // Check the length
        assertEquals( 0x08, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * empty  newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordEmpty()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0A );
        bb.put( new byte[]
            { 0x30, 0x08, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x00
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( 0, pwdModifyRequest.getNewPassword().length );

        // Check the length
        assertEquals( 0x0A, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test the decoding of a PasswordModifyRequest with an oldPassword and an
     * newPassword
     */
    @Test
    public void testDecodePasswordModifyRequestOldPasswordValueNewPasswordValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x0E );
        bb.put( new byte[]
            { 0x30, 0x0C, // PasswordModifyRequest ::= SEQUENCE {
                ( byte ) 0x81,
                0x04, // oldPassword    [1]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd',
                ( byte ) 0x82, // newPassword    [2]  OCTET STRING OPTIONAL
                0x04,
                'e',
                'f',
                'g',
                'h'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyRequest pwdModifyRequest = container.getPwdModifyRequest();
        assertNull( pwdModifyRequest.getUserIdentity() );
        assertNotNull( pwdModifyRequest.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequest.getOldPassword() ) );
        assertNotNull( pwdModifyRequest.getNewPassword() );
        assertEquals( "efgh", Strings.utf8ToString( pwdModifyRequest.getNewPassword() ) );

        // Check the length
        assertEquals( 0x0E, ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyRequestDecorator ) pwdModifyRequest ).encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb1.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }
}
