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
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyResponseContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify.PasswordModifyResponseDecorator;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the PasswordModifyReponse codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class PasswordModifyResponseTest
{
    /**
     * Test the decoding of a PasswordModifyResponse with nothing in it
     */
    @Test
    public void testDecodePasswordModifyResponseEmpty()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x02 );
        bb.put( new byte[]
            { 0x30, 0x00, // PasswordModifyResponse ::= SEQUENCE {
            } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyResponse pwdModifyResponse = container.getPwdModifyResponse();
        assertNull( pwdModifyResponse.getGenPassword() );

        // Check the length
        assertEquals( 0x02, ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).encodeInternal();

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
     * Test the decoding of a PasswordModifyResponse with an empty genPassword
     */
    @Test
    public void testDecodePasswordModifyResponseUserIdentityNull()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x04 );
        bb.put( new byte[]
            { 0x30, 0x02, // PasswordModifyResponse ::= SEQUENCE {
                ( byte ) 0x80,
                0x00 // genPassword    [0]  OCTET STRING OPTIONAL
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyResponse pwdModifyResponse = container.getPwdModifyResponse();
        assertNotNull( pwdModifyResponse.getGenPassword() );
        assertEquals( 0, pwdModifyResponse.getGenPassword().length );

        // Check the length
        assertEquals( 0x04, ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).encodeInternal();

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
     * Test the decoding of a PasswordModifyResponse with a genPassword
     */
    @Test
    public void testDecodePasswordModifyResponseUserIdentityValue()
    {
        Asn1Decoder decoder = new Asn1Decoder();
        ByteBuffer bb = ByteBuffer.allocate( 0x08 );
        bb.put( new byte[]
            { 0x30, 0x06, // PasswordModifyResponse ::= SEQUENCE {
                ( byte ) 0x80,
                0x04, // genPassword    [0]  OCTET STRING OPTIONAL
                'a',
                'b',
                'c',
                'd'
        } );

        String decodedPdu = Strings.dumpBytes( bb.array() );
        bb.flip();

        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();

        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        PasswordModifyResponse pwdModifyResponse = container.getPwdModifyResponse();
        assertNotNull( pwdModifyResponse.getGenPassword() );
        assertEquals( "abcd", Strings.utf8ToString( pwdModifyResponse.getGenPassword() ) );

        // Check the length
        assertEquals( 0x08, ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).computeLengthInternal() );

        // Check the encoding
        try
        {
            ByteBuffer bb1 = ( ( PasswordModifyResponseDecorator ) pwdModifyResponse ).encodeInternal();

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
