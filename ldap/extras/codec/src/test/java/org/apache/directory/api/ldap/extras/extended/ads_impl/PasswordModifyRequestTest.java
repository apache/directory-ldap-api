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
package org.apache.directory.api.ldap.extras.extended.ads_impl;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdown;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown.GracefulShutdownContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyRequestContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyRequestDecorator;
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
     * Test the decoding of a PasswordModifyRequest
     */
    @Test
    public void testDecodePasswordModifyRequestSuccess()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 0x30, 0x06, // GracefulShutdown ::= SEQUENCE {
                0x02,
                0x01,
                0x01, // timeOffline INTEGER (0..720) DEFAULT 0,
                ( byte ) 0x80,
                0x01,
                0x01 // delay INTEGER (0..86400) DEFAULT
                     // 0
            // }
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        GracefulShutdownContainer container = new GracefulShutdownContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        GracefulShutdown gracefulShutdown = container.getGracefulShutdown();
        assertEquals( 1, gracefulShutdown.getTimeOffline() );
        assertEquals( 1, gracefulShutdown.getDelay() );

        // Check the length
        assertEquals( 0x08, gracefulShutdown.computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = gracefulShutdown.encode();

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

        PasswordModifyRequestDecorator pwdModifyRequestDecorator = container.getPasswordModifyRequest();
        assertNull( pwdModifyRequestDecorator.getUserIdentity() );
        assertNull( pwdModifyRequestDecorator.getOldPassword() );
        assertNull( pwdModifyRequestDecorator.getNewPassword() );

        // Check the length
        assertEquals( 0x02, pwdModifyRequestDecorator.getPasswordModifyRequest().computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = pwdModifyRequestDecorator.getPasswordModifyRequest().encode();

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

        PasswordModifyRequestDecorator pwdModifyRequestDecorator = container.getPasswordModifyRequest();
        assertNotNull( pwdModifyRequestDecorator.getUserIdentity() );
        assertEquals( 0, pwdModifyRequestDecorator.getUserIdentity().length );
        assertNull( pwdModifyRequestDecorator.getOldPassword() );
        assertNull( pwdModifyRequestDecorator.getNewPassword() );

        // Check the length
        assertEquals( 0x04, pwdModifyRequestDecorator.getPasswordModifyRequest().computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = pwdModifyRequestDecorator.getPasswordModifyRequest().encode();

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

        PasswordModifyRequestDecorator pwdModifyRequestDecorator = container.getPasswordModifyRequest();
        assertNotNull( pwdModifyRequestDecorator.getUserIdentity() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequestDecorator.getUserIdentity() ) );
        assertNull( pwdModifyRequestDecorator.getOldPassword() );
        assertNull( pwdModifyRequestDecorator.getNewPassword() );

        // Check the length
        assertEquals( 0x08, pwdModifyRequestDecorator.getPasswordModifyRequest().computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = pwdModifyRequestDecorator.getPasswordModifyRequest().encode();

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

        PasswordModifyRequestDecorator pwdModifyRequestDecorator = container.getPasswordModifyRequest();
        assertNull( pwdModifyRequestDecorator.getUserIdentity() );
        assertNotNull( pwdModifyRequestDecorator.getOldPassword() );
        assertEquals( 0, pwdModifyRequestDecorator.getOldPassword().length );
        assertNull( pwdModifyRequestDecorator.getNewPassword() );

        // Check the length
        assertEquals( 0x04, pwdModifyRequestDecorator.getPasswordModifyRequest().computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = pwdModifyRequestDecorator.getPasswordModifyRequest().encode();

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
                0x04, // oldPassword    [0]  OCTET STRING OPTIONAL
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

        PasswordModifyRequestDecorator pwdModifyRequestDecorator = container.getPasswordModifyRequest();
        assertNull( pwdModifyRequestDecorator.getUserIdentity() );
        assertNotNull( pwdModifyRequestDecorator.getOldPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyRequestDecorator.getOldPassword() ) );
        assertNull( pwdModifyRequestDecorator.getNewPassword() );

        // Check the length
        assertEquals( 0x08, pwdModifyRequestDecorator.getPasswordModifyRequest().computeLength() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = pwdModifyRequestDecorator.getPasswordModifyRequest().encode();

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
