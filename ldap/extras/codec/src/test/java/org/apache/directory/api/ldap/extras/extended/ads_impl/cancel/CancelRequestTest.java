/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */

package org.apache.directory.api.ldap.extras.extended.ads_impl.cancel;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * TestCase for a Cancel Extended Operation request
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class CancelRequestTest
{
    private static LdapApiService codec;

    @BeforeAll
    public static void init()
    {
        codec = new DefaultLdapCodecService();
        codec.registerExtendedRequest( new CancelFactory( codec ) );
    }
    
    
    /**
     * Test the normal Cancel message
     */
    @Test
    public void testDecodeCancel() throws DecoderException, EncoderException
    {
        byte[] stream = new byte[]
            {
                0x30, 0x03,
                  0x02, 0x01, 0x01
            };

        CancelFactory factory = ( CancelFactory ) codec.getExtendedRequestFactories().
            get( CancelRequest.EXTENSION_OID );
        CancelRequest cancelRequest = ( CancelRequest ) factory.newRequest( stream );

        assertEquals( 1, cancelRequest.getCancelId() );

        // Check the reverse decoding
        Asn1Buffer asn1Buffer = new Asn1Buffer();
        factory.encodeValue( asn1Buffer, cancelRequest );
        assertArrayEquals( stream,  asn1Buffer.getBytes().array() );
    }


    /**
     * Test a Cancel message with no cancelId
     */
    @Test
    public void testDecodeCancelNoCancelId() throws DecoderException
    {
        byte[] stream = new byte[]
            {
                0x30, 0x00
            };

        CancelFactory factory = ( CancelFactory ) codec.getExtendedRequestFactories().
            get( CancelRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( stream );
        } );
    }


    /**
     * Test a Cancel message with an empty cancelId
     */
    @Test
    public void testDecodeCancelEmptyCancelId() throws DecoderException
    {
        byte[] stream = new byte[]
            {
                0x30, 0x02,
                  0x02, 0x00
            };

        CancelFactory factory = ( CancelFactory ) codec.getExtendedRequestFactories().
            get( CancelRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( stream );
        } );
    }


    /**
     * Test a Cancel message with a bad cancelId
     */
    @Test
    public void testDecodeCancelBadCancelId() throws DecoderException
    {
        byte[] stream = new byte[]
            {
                0x30, 0x06,
                  0x02, 0x04, 
                    ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF, ( byte ) 0xFF
            };

        CancelFactory factory = ( CancelFactory ) codec.getExtendedRequestFactories().
            get( CancelRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( stream );
        } );
    }


    /**
     * Test a Cancel message with more than one cancelId
     */
    @Test
    public void testDecodeCancelMoreThanOneCancelId() throws DecoderException
    {
        byte[] stream = new byte[]
            {
                0x30, 0x06,
                  0x02, 0x01, 0x01,
                  0x02, 0x01, 0x02
            };

        CancelFactory factory = ( CancelFactory ) codec.getExtendedRequestFactories().
            get( CancelRequest.EXTENSION_OID );

        assertThrows( DecoderException.class, ( ) ->
        {
            factory.newRequest( stream );
        } );
    }
}
