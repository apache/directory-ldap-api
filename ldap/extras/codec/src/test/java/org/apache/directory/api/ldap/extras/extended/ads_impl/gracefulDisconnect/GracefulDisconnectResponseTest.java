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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect;


import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.util.Iterator;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.extras.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the GracefulDisconnectTest codec
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class GracefulDisconnectResponseTest extends AbstractCodecServiceTest
{
    @Before
    public void init()
    {
        codec.registerExtendedResponse( new GracefulDisconnectFactory( codec ) );
    }
    
    
    /**
     * Test the decoding of a GracefulDisconnect
     */
    @Test
    public void testDecodeGracefulDisconnectSuccess() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x6E,                             // GracefulDisconnec ::= SEQUENCE {
                  0x02, 0x01, 0x01,                     // timeOffline INTEGER (0..720) DEFAULT 0,
                  ( byte ) 0x80, 0x01, 0x01,            // delay INTEGER (0..86400) DEFAULT 0
                    0x30, 0x66,                         // replicatedContexts Referral OPTIONAL
                      0x04, 0x1F,     
                        'l', 'd', 'a', 'p', ':', '/', '/', 'd',
                        'i', 'r', 'e', 'c', 't', 'o', 'r', 'y',
                        '.', 'a', 'p', 'a', 'c', 'h', 'e', '.',
                        'o', 'r', 'g', ':', '8', '0', '/',
                      0x04, 0x43,
                        'l', 'd', 'a', 'p', ':', '/', '/', 'l', 
                        'd', 'a', 'p', '.', 'n', 'e', 't', 's', 
                        'c', 'a', 'p', 'e', '.', 'c', 'o', 'm', 
                        '/', 'o', '=', 'B', 'a', 'b', 's', 'c', 
                        'o', ',', 'c', '=', 'U', 'S', '?', '?', 
                        '?', '(', 'i', 'n', 't', '=', '%', '5', 
                        'c', '0', '0', '%', '5', 'c', '0', '0', 
                        '%', '5', 'c', '0', '0', '%', '5', 'c', 
                        '0', '4', ')'
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 2, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );
        
        Iterator<String> ldapUrls = gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().iterator();
        assertEquals( "ldap://directory.apache.org:80/", ldapUrls.next() );
        assertEquals( "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)", ldapUrls.next() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline only
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOffline() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,             // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x01, 0x01      // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a delay only
     */
    @Test
    public void testDecodeGracefulDisconnectDelay() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x03,                     // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x01, 0x01     // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );


        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline and a delay
     */
    @Test
    public void testDecodeGracefulDisconnectTimeOfflineDelay() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x06,                     // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x01, 0x01,             // timeOffline INTEGER (0..720) DEFAULT 0,
                  ( byte ) 0x80, 0x01, 0x01,    // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 1, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 1, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a GracefulDisconnect with replicatedContexts only
     */
    @Test
    public void testDecodeGracefulDisconnectReplicatedContextsOnly() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            {
                0x30, 0x68,             // GracefulDisconnec ::= SEQUENCE {
                  0x30, 0x66,           // replicatedContexts Referral OPTIONAL
                    0x04, 0x1F,     
                      'l', 'd', 'a', 'p', ':', '/', '/', 'd',
                      'i', 'r', 'e', 'c', 't', 'o', 'r', 'y',
                      '.', 'a', 'p', 'a', 'c', 'h', 'e', '.',
                      'o', 'r', 'g', ':', '8', '0', '/',
                    0x04, 0x43,
                      'l', 'd', 'a', 'p', ':', '/', '/', 'l', 
                      'd', 'a', 'p', '.', 'n', 'e', 't', 's', 
                      'c', 'a', 'p', 'e', '.', 'c', 'o', 'm', 
                      '/', 'o', '=', 'B', 'a', 'b', 's', 'c', 
                      'o', ',', 'c', '=', 'U', 'S', '?', '?', 
                      '?', '(', 'i', 'n', 't', '=', '%', '5', 
                      'c', '0', '0', '%', '5', 'c', '0', '0', 
                      '%', '5', 'c', '0', '0', '%', '5', 'c', 
                      '0', '4', ')'

            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 2, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );
        
        Iterator<String> ldapUrls = gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().iterator();
        assertEquals( "ldap://directory.apache.org:80/", ldapUrls.next() );
        assertEquals( "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)", ldapUrls.next() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    /**
     * Test the decoding of a empty GracefulDisconnect
     */
    @Test
    public void testDecodeGracefulDisconnectEmpty() throws DecoderException, EncoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x00 // GracefulDisconnect ::= SEQUENCE {
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        GracefulDisconnectResponse gracefulDisconnectResponse = ( GracefulDisconnectResponse ) factory.newResponse( bb );

        assertEquals( 0, gracefulDisconnectResponse.getTimeOffline() );
        assertEquals( 0, gracefulDisconnectResponse.getDelay() );
        assertEquals( 0, gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();

        factory.encodeValue( asn1Buffer, gracefulDisconnectResponse );

        assertArrayEquals( bb, asn1Buffer.getBytes().array() );
    }


    // Defensive tests

    /**
     * Test the decoding of a GracefulDisconnect with a timeOffline off limit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectTimeOfflineOffLimit() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,                         // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x02, 0x03, ( byte ) 0xE8   // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }


    /**
     * Test the decoding of a GracefulDisconnect with a delay off limit
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectDelayOffLimit() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x05,                             // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x03,
                    0x01, ( byte ) 0x86, ( byte ) 0xA0  // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty TimeOffline
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectTimeOfflineEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,         // GracefulDisconnect ::= SEQUENCE {
                  0x02, 0x00        // timeOffline INTEGER (0..720) DEFAULT 0,
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty delay
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectDelayEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,                 // GracefulDisconnect ::= SEQUENCE {
                  ( byte ) 0x80, 0x00       // delay INTEGER (0..86400) DEFAULT 0
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an empty replicated
     * contexts
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectReplicatedContextsEmpty() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x02,         // GracefulDisconnect ::= SEQUENCE {
                  0x30, 0x00        // replicatedContexts Referral OPTIONAL
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }


    /**
     * Test the decoding of a GracefulDisconnect with an invalid replicated
     * context
     */
    @Test( expected=DecoderException.class )
    public void testDecodeGracefulDisconnectReplicatedContextsInvalid() throws DecoderException
    {
        byte[] bb = new byte[]
            { 
                0x30, 0x04,             // GracefulDisconnect ::= SEQUENCE {
                  0x30, 0x02,           // replicatedContexts Referral OPTIONAL
                    0x04, 0x00 
            };

        GracefulDisconnectFactory factory = ( GracefulDisconnectFactory ) codec.getExtendedResponseFactories().
            get( GracefulDisconnectResponse.EXTENSION_OID );
        factory.newResponse( bb );
    }
}
