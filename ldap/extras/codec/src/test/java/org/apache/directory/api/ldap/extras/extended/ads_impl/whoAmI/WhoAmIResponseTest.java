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


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
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
public class WhoAmIResponseTest extends AbstractCodecServiceTest
{
    /**
     * Test the normal WhoAmI response message
     */
    @Test
    public void testDecodeWhoAmINull() throws DecoderException, EncoderException
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer bb = ByteBuffer.allocate( 0x00 );

        bb.put( new byte[]
            {} ).flip();

        Strings.dumpBytes( bb.array() );

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        whoAmIResponseDecoder.decode( bb, whoAmIResponseContainer );

        WhoAmIResponseDecorator whoAmIResponse = ( ( WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNull( whoAmIResponse.getAuthzId() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        WhoAmIFactory factory = new WhoAmIFactory( codec );
        factory.encodeValue( asn1Buffer, whoAmIResponse );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test a WhoAmI message with a DN authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdDN() throws DecoderException, EncoderException
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x0C );

        stream.put( new byte[]
            {
                'd', 'n', ':', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } ).flip();

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        
        WhoAmIResponseDecorator whoAmIResponse = ( ( WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNotNull( whoAmIResponse.getAuthzId() );
        assertEquals( "dn:ou=system", Strings.utf8ToString( whoAmIResponse.getAuthzId() ) );
        

        // Check the encoding
        ByteBuffer bb = whoAmIResponse.encodeInternal();

        assertArrayEquals( stream.array(), bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        WhoAmIFactory factory = new WhoAmIFactory( codec );
        factory.encodeValue( asn1Buffer, whoAmIResponse );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test a WhoAmI message with a UserId authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdUserId() throws DecoderException, EncoderException
    {
        Asn1Decoder whoAmIResponseDecoder = new WhoAmIResponseDecoder();

        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                'u', ':', 't', 'e', 's', 't', 0x00
            } ).flip();

        // Allocate a WhoAmI Container
        Asn1Container whoAmIResponseContainer = new WhoAmIResponseContainer();

        // Decode a WhoAmI message
        whoAmIResponseDecoder.decode( stream, whoAmIResponseContainer );
        
        WhoAmIResponseDecorator whoAmIResponse = ( (WhoAmIResponseContainer ) whoAmIResponseContainer ).getWhoAmIResponse();

        assertNotNull( whoAmIResponse.getAuthzId() );

        // Check the encoding
        ByteBuffer bb = whoAmIResponse.encodeInternal();

        assertArrayEquals( stream.array(), bb.array() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        WhoAmIFactory factory = new WhoAmIFactory( codec );
        factory.encodeValue( asn1Buffer, whoAmIResponse );
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }
}
