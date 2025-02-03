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
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Message;

/**
 * The BindResponse factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class BindResponseFactory extends ResponseFactory
{
    /** The static instance */
    public static final BindResponseFactory INSTANCE = new BindResponseFactory();

    /**
     * A default private constructor
     */
    private BindResponseFactory()
    {
        super();
    }


    /**
     * Encode the BindResponse message to a PDU.
     * <br>
     * BindResponse :
     * <pre>
     * 0x61 L1
     *  |
     *  +--&gt; LdapResult
     * [+--0x87 LL serverSaslCreds]
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the BindResponse to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        int start = buffer.getPos();
        BindResponse bindResponse = ( ( BindResponse ) message );

        // The serverSASL creds, if any
        byte[] serverSaslCreds = bindResponse.getServerSaslCreds();

        if ( serverSaslCreds != null )
        {
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.SERVER_SASL_CREDENTIAL_TAG,
                serverSaslCreds );
        }

        // The LDAPResult part
        encodeLdapResultReverse( buffer, bindResponse.getLdapResult() );

        // The BindResponse Tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.BIND_RESPONSE_TAG, start );
    }
}
