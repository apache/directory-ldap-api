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
package org.apache.directory.api.ldap.codec.factory;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.util.Strings;

/**
 * The IntermediateResponse factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class IntermediateResponseFactory extends ResponseFactory
{
    /** The static instance */
    public static final IntermediateResponseFactory INSTANCE = new IntermediateResponseFactory();

    /**
     * A default private constructor
     */
    private IntermediateResponseFactory()
    {
        super();
    }


    /**
     * Encode the IntermediateResponse message to a PDU.
     * <br>
     * IntermediateResponse :
     * <pre>
     * 0x78 L1
     *  |
     * [+--&gt; 0x80 LL abcd responseName]
     * [+--&gt; 0x81 LL abcd responseValue]
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the IntermediateResponse to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        IntermediateResponse intermediateResponse = ( IntermediateResponse ) message;
        
        // The responseValue, if any
        IntermediateOperationFactory factory = codec.getIntermediateResponseFactories().
            get( intermediateResponse.getResponseName() );
        
        if ( factory != null )
        {
            factory.encodeValue( buffer, intermediateResponse );

            if ( buffer.getPos() > start )
            { 
                BerValue.encodeSequence( buffer, 
                    ( byte ) LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG,
                    start );
            }
        }
        else if ( !Strings.isEmpty( intermediateResponse.getResponseValue() ) )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) LdapCodecConstants.INTERMEDIATE_RESPONSE_VALUE_TAG,
                intermediateResponse.getResponseValue() );
        }
        
        // The responseName, if any
        if ( !Strings.isEmpty( intermediateResponse.getResponseName() ) )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) LdapCodecConstants.INTERMEDIATE_RESPONSE_NAME_TAG,
                intermediateResponse.getResponseName() );
        }

        // The sequence
        BerValue.encodeSequence( buffer, LdapCodecConstants.INTERMEDIATE_RESPONSE_TAG, start );
    }
}
