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
package org.apache.directory.api.ldap.codec.factory;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.OpaqueExtendedResponse;
import org.apache.directory.api.util.Strings;

/**
 * The ExtendedResponse factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ExtendedResponseFactory extends ResponseFactory
{
    /** The static instance */
    public static final ExtendedResponseFactory INSTANCE = new ExtendedResponseFactory();

    private ExtendedResponseFactory()
    {
        super();
    }


    /**
     * Encode the ExtendedResponse message to a PDU.
     * <br>
     * ExtendedResponse :
     * <pre>
     * 0x78 L1
     *  |
     *  +--&gt; LdapResult
     * [+--&gt; 0x8A LL abcd responseName]
     * [+--&gt; 0x8B LL abcd responseValue]
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the ExtendedResponse to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        ExtendedResponse extendedResponse = ( ExtendedResponse ) message;
        
        // The responseValue, if any
        ExtendedOperationFactory factory = codec.getExtendedResponseFactories().
            get( extendedResponse.getResponseName() );
        
        if ( factory != null )
        {
            factory.encodeValue( buffer, extendedResponse );

            if ( buffer.getPos() > start )
            { 
                BerValue.encodeSequence( buffer, 
                    ( byte ) LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG,
                    start );
            }
        }
        else
        {
            byte[] responseValue = ( ( OpaqueExtendedResponse ) extendedResponse ).getResponseValue();
            
            if ( !Strings.isEmpty( responseValue ) )
            {
                BerValue.encodeOctetString( buffer, 
                    ( byte ) LdapCodecConstants.EXTENDED_RESPONSE_VALUE_TAG, responseValue );
            }
        }
        
        // The responseName, if any
        if ( !Strings.isEmpty( extendedResponse.getResponseName() ) )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) LdapCodecConstants.EXTENDED_RESPONSE_NAME_TAG,
                extendedResponse.getResponseName() );
        }
        
        // The LDAPResult part
        encodeLdapResultReverse( buffer, extendedResponse.getLdapResult() );

        // The sequence
        BerValue.encodeSequence( buffer, LdapCodecConstants.EXTENDED_RESPONSE_TAG, start );
    }
}
