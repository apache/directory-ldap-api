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
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;

/**
 * The BindRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class BindRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final BindRequestFactory INSTANCE = new BindRequestFactory();

    private BindRequestFactory()
    {
        // Nothing to do
    }

    /**
     * Encode the BindRequest message to a PDU.
     * <br>
     * BindRequest :
     * <pre>
     * 0x60 LL
     *   0x02 LL version         0x80 LL simple
     *   0x04 LL name           /
     *   authentication.encode()
     *                          \ 0x83 LL 0x04 LL mechanism [0x04 LL credential]
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param message the BindRequest to encode
     */
    @Override
    public void encodeReverse( Asn1Buffer buffer, Message message )
    {
        int pos = buffer.getPos();
        BindRequest bindMessage = ( BindRequest ) message;

        // The authentication
        if ( bindMessage.isSimple() )
        {
            // Simple authentication
            BerValue.encodeOctetString( buffer, ( byte ) LdapCodecConstants.BIND_REQUEST_SIMPLE_TAG, bindMessage.getCredentials() );
        }
        else
        {
            // SASL Bind
            // The credentials, if any
            if ( !Strings.isEmpty( bindMessage.getCredentials() ) )
            {
                BerValue.encodeOctetString( buffer, bindMessage.getCredentials() );
            }

            // The mechanism
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( bindMessage.getSaslMechanism() ) );

            // The SASL tag
            BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.BIND_REQUEST_SASL_TAG );
        }

        // The name
        Dn dn = bindMessage.getDn();

        if ( !Dn.isNullOrEmpty( dn ) )
        {
            // A DN has been provided
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( dn.getName() ) );
        }
        else
        {
            // No DN has been provided, let's use the name as a string instead
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( bindMessage.getName() ) );
        }

        // The version (LDAP V3 only)
        BerValue.encodeInteger( buffer, 3 );

        // The BindRequest Tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.BIND_REQUEST_TAG, pos );
    }
}
