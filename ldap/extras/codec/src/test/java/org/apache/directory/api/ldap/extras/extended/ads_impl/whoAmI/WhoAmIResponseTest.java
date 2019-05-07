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


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/*
 * TestCase for a WhoAmI response Extended Operation
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class WhoAmIResponseTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedResponse( new WhoAmIFactory( codec ) );
    }

    
    /**
     * Test the normal WhoAmI response message
     */
    @Test
    public void testDecodeWhoAmINull() throws DecoderException, EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( 0x00 );

        bb.put( new byte[]
            {} ).flip();

        // Decode a WhoAmI message
        WhoAmIFactory factory = ( WhoAmIFactory ) codec.getExtendedResponseFactories().
            get( WhoAmIResponse.EXTENSION_OID );
        WhoAmIResponse whoAmIResponse = factory.newResponse();
        factory.decodeValue( whoAmIResponse, bb.array() );

        assertNull( whoAmIResponse.getAuthzId() );
        
        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, whoAmIResponse );
        
        assertArrayEquals( bb.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test a WhoAmI message with a DN authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdDN() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x0C );

        stream.put( new byte[]
            {
                'd', 'n', ':', 'o', 'u', '=', 's', 'y', 's', 't', 'e', 'm'
            } ).flip();

        // Decode a WhoAmI message
        WhoAmIFactory factory = ( WhoAmIFactory ) codec.getExtendedResponseFactories().
            get( WhoAmIResponse.EXTENSION_OID );
        WhoAmIResponse whoAmIResponse = factory.newResponse();
        factory.decodeValue( whoAmIResponse, stream.array() );

        assertNotNull( whoAmIResponse.getAuthzId() );
        assertEquals( "dn:ou=system", Strings.utf8ToString( whoAmIResponse.getAuthzId() ) );
        

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, whoAmIResponse );

       assertArrayEquals( stream.array(), asn1Buffer.getBytes().array() );
    }


    /**
     * Test a WhoAmI message with a UserId authzId
     */
    @Test
    public void testDecodeWhoAmINoWhoAmIAuthzIdUserId() throws DecoderException, EncoderException
    {
        ByteBuffer stream = ByteBuffer.allocate( 0x07 );

        stream.put( new byte[]
            {
                'u', ':', 't', 'e', 's', 't', 0x00
            } ).flip();

        // Decode a WhoAmI message
        WhoAmIFactory factory = ( WhoAmIFactory ) codec.getExtendedResponseFactories().
            get( WhoAmIResponse.EXTENSION_OID );
        WhoAmIResponse whoAmIResponse = factory.newResponse();
        factory.decodeValue( whoAmIResponse, stream.array() );

        assertNotNull( whoAmIResponse.getAuthzId() );

        // Check the reverse encoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, whoAmIResponse );

        assertArrayEquals( stream.array(), asn1Buffer.getBytes().array() );
    }
}
