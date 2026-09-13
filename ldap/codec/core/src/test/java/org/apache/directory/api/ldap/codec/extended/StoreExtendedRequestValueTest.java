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
package org.apache.directory.api.ldap.codec.extended;


import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Checks that decoding an ExtendedRequest value does not assume the request produced
 * by a registered {@link org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory}
 * extends OpaqueExtendedRequest : the public contract only requires an
 * {@link ExtendedRequest}, and a remote PDU must not be able to trigger a
 * ClassCastException out of the decoder.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class StoreExtendedRequestValueTest
{
    private static final String CUSTOM_OID = "1.2.3.4.5";

    /** An extended request that follows the public API but does NOT extend OpaqueExtendedRequest */
    private static final class CustomExtendedRequest extends AbstractExtendedRequest
    {
        private byte[] value;

        CustomExtendedRequest()
        {
            setRequestName( CUSTOM_OID );
        }


        @Override
        public ExtendedResponse getResultResponse()
        {
            return null;
        }
    }

    private static final class CustomExtendedOperationFactory extends AbstractExtendedOperationFactory
    {
        CustomExtendedOperationFactory( LdapApiService codec )
        {
            super( codec, CUSTOM_OID );
        }


        @Override
        public ExtendedRequest newRequest()
        {
            return new CustomExtendedRequest();
        }


        @Override
        public void decodeValue( ExtendedRequest extendedRequest, byte[] requestValue )
        {
            ( ( CustomExtendedRequest ) extendedRequest ).value = requestValue;
        }


        @Override
        public ExtendedResponse newResponse() throws DecoderException
        {
            return null;
        }
    }


    /**
     * Decode an ExtendedRequest whose registered factory produces a request that is
     * not an OpaqueExtendedRequest : the value must be handed to the factory, with
     * no ClassCastException.
     *
     * @throws DecoderException If the ASN1 decoding failed
     */
    @Test
    public void testDecodeExtendedRequestValueWithNonOpaqueRequest() throws DecoderException
    {
        DefaultLdapCodecService codec = new DefaultLdapCodecService();
        codec.getExtendedRequestFactories().put( CUSTOM_OID, new CustomExtendedOperationFactory( codec ) );

        ByteBuffer stream = ByteBuffer.allocate( 0x17 );

        stream.put( new byte[]
            {
                0x30, 0x15,                 // LDAPMessage ::= SEQUENCE {
                  0x02, 0x01, 0x01,         // messageID MessageID
                                            // CHOICE { ..., extendedReq ExtendedRequest, ...
                  0x77, 0x10,               // ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
                                            // requestName [0] LDAPOID,
                  ( byte ) 0x80, 0x09,
                    '1', '.', '2', '.', '3', '.', '4', '.', '5',
                                            // requestValue [1] OCTET STRING OPTIONAL }
                  ( byte ) 0x81, 0x03,
                    'a', 'b', 'c'
            } );

        stream.flip();

        LdapMessageContainer<ExtendedRequest> container = new LdapMessageContainer<>( codec );

        // Decode the PDU : must not throw a ClassCastException
        Asn1Decoder.decode( stream, container );

        ExtendedRequest extendedRequest = container.getMessage();

        assertTrue( extendedRequest instanceof CustomExtendedRequest );
        assertEquals( CUSTOM_OID, extendedRequest.getRequestName() );
        assertEquals( 1, extendedRequest.getMessageId() );
        assertArrayEquals( new byte[] { 'a', 'b', 'c' }, ( ( CustomExtendedRequest ) extendedRequest ).value );
    }
}
