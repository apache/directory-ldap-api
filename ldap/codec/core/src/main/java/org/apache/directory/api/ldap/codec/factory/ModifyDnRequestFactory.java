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

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.util.Strings;

/**
 * The ModifyDnRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class ModifyDnRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final ModifyDnRequestFactory INSTANCE = new ModifyDnRequestFactory();

    private ModifyDnRequestFactory()
    {
        // Nothing to do
    }


    /**
     * Encode the ModifyDnRequest message to a PDU.
     * <br>
     * ModifyDNRequest :
     * <pre>
     * 0x6C LL
     *   0x04 LL entry
     *   0x04 LL newRDN
     *   0x01 0x01 deleteOldRDN
     *   [0x80 LL newSuperior]
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the ModifyRequest to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message ) throws EncoderException
    {
        int start = buffer.getPos();
        ModifyDnRequest modifyDnRequest = ( ModifyDnRequest ) message;

        if ( modifyDnRequest.getNewSuperior() != null )
        {
            // Encode the new superior
            BerValue.encodeOctetString( buffer,
                ( byte ) LdapCodecConstants.MODIFY_DN_REQUEST_NEW_SUPERIOR_TAG,
                Strings.getBytesUtf8( modifyDnRequest.getNewSuperior().getName() ) );
        }

        // The deleteOldRdn flag
        BerValue.encodeBoolean( buffer, modifyDnRequest.getDeleteOldRdn() );

        // The new RDN
        Rdn newRdn = modifyDnRequest.getNewRdn();
        
        if ( newRdn == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_03023_NEW_RDN_ATTRIBUTE_REQUESTED ) );
        }
        
        BerValue.encodeOctetString( buffer, newRdn.getName() );

        // The entry DN
        Dn name = modifyDnRequest.getName();
        
        if ( name == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_03022_NULL_REQUEST_NAME ) );
        }
            
        BerValue.encodeOctetString( buffer, name.getName() );

        // The ModifyDnRequest tag
        BerValue.encodeSequence( buffer, LdapCodecConstants.MODIFY_DN_REQUEST_TAG, start );
    }
}
