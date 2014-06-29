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

package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.util.Strings;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/*
 * TestCase for a WhoAmI response Extended Operation
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class WhoAmIResponseTest
{
    /**
     * Test the normal WhoAmI response message
     */
    @Test
    public void testDecodeWhoAmINull()
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x00 );

        stream.put( new byte[]
            {} ).flip();

        Strings.dumpBytes( stream.array() );

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        try
        {
            whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        }
        catch ( DecoderException de )
        {
            de.printStackTrace();
            fail( de.getMessage() );
        }

        WhoAmIResponseDecorator whoAmIResponse = ( ( WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNull( whoAmIResponse );
    }


    /**
     * Test a WhoAmI message with no authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdEmpty()
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x02 );

        stream.put( new byte[]
            {
                0x04, 0x00
        } ).flip();

        String decodedPdu = Strings.dumpBytes( stream.array() );

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        try
        {
            whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        }
        catch ( DecoderException de )
        {
            fail();
        }
        
        WhoAmIResponseDecorator whoAmIResponse = ( (WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNull( whoAmIResponse.getAuthzId() );

        // Check the encoding
        try
        {
            ByteBuffer bb = whoAmIResponse.encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test a WhoAmI message with a DN authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdDN()
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0E );

        stream.put( new byte[]
            {
                0x04, 0x0C,
                  'd', 'n', ':', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
        } ).flip();

        String decodedPdu = Strings.dumpBytes( stream.array() );

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        try
        {
            whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        }
        catch ( DecoderException de )
        {
            fail();
        }
        
        WhoAmIResponseDecorator whoAmIResponse = ( (WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNotNull( whoAmIResponse.getAuthzId() );
        assertEquals( "dn:ou=system", Strings.utf8ToString( whoAmIResponse.getAuthzId() ) );
        

        // Check the encoding
        try
        {
            ByteBuffer bb = whoAmIResponse.encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }


    /**
     * Test a WhoAmI message with a UserId authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdUserId()
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x09 );

        stream.put( new byte[]
            {
                0x04, 0x07,
                  'u', ':', 't', 'e', 's', 't', 0x00
        } ).flip();

        String decodedPdu = Strings.dumpBytes( stream.array() );

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        try
        {
            whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        }
        catch ( DecoderException de )
        {
            fail();
        }
        
        WhoAmIResponseDecorator whoAmIResponse = ( (WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNotNull( whoAmIResponse.getAuthzId() );

        // Check the encoding
        try
        {
            ByteBuffer bb = whoAmIResponse.encodeInternal();

            String encodedPdu = Strings.dumpBytes( bb.array() );

            assertEquals( encodedPdu, decodedPdu );
        }
        catch ( EncoderException ee )
        {
            ee.printStackTrace();
            fail( ee.getMessage() );
        }
    }
}
