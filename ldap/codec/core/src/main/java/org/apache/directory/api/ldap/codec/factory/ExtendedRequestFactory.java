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
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.util.Strings;

/**
 * The ExtendedRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ExtendedRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final ExtendedRequestFactory INSTANCE = new ExtendedRequestFactory();

    private ExtendedRequestFactory()
    {
        super();
    }


    /**
     * Encode the ExtendedRequest message to a PDU.
     * <br>
     * ExtendedRequest :
     * <pre>
     * 0x77 L1
     *  |
     *  +--&gt; 0x80 LL abcd requestName
     * [+--&gt; 0x81 LL abcd requestValue]
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the DeleteResponse to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        ExtendedRequest extendedRequest = ( ExtendedRequest ) message;
        
        // The responseValue, if any
        ExtendedOperationFactory factory = codec.getExtendedRequestFactories().
            get( extendedRequest.getRequestName() );
        
        if ( factory != null )
        {
            factory.encodeValue( buffer, extendedRequest );

            if ( buffer.getPos() > start )
            {
                BerValue.encodeSequence( buffer, 
                    ( byte ) LdapCodecConstants.EXTENDED_REQUEST_VALUE_TAG,
                    start );
            }
        }
        
        // The responseName, if any
        if ( !Strings.isEmpty( extendedRequest.getRequestName() ) )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) LdapCodecConstants.EXTENDED_REQUEST_NAME_TAG,
                extendedRequest.getRequestName() );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, LdapCodecConstants.EXTENDED_REQUEST_TAG, start );
    }
}
