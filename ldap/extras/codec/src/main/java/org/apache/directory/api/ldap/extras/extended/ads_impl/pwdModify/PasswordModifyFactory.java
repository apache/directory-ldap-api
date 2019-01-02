/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating PwdModify extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of PasswordModifyFactory.
     *
     * @param codec The codec for this factory.
     */
    public PasswordModifyFactory( LdapApiService codec )
    {
        super( codec, PasswordModifyRequest.EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyRequest newRequest()
    {
        PasswordModifyRequest passwordModifyRequest = new PasswordModifyRequestImpl();

        return passwordModifyRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyRequest newRequest( byte[] encodedValue ) throws DecoderException
    {
        PasswordModifyRequest passwordModifyRequest = new PasswordModifyRequestImpl();
        decodeValue( passwordModifyRequest, encodedValue );

        return passwordModifyRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyResponse newResponse()
    {
        PasswordModifyResponse passwordModifyResponse = new PasswordModifyResponseImpl();
        
        return passwordModifyResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        PasswordModifyResponse passwordModifyResponse = new PasswordModifyResponseImpl();
        decodeValue( passwordModifyResponse, encodedValue );

        return passwordModifyResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedRequest extendedRequest, byte[] requestValue ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( requestValue );
        PasswordModifyRequestContainer container = new PasswordModifyRequestContainer();
        container.setPasswordModifyRequest( ( PasswordModifyRequest ) extendedRequest ); 
        Asn1Decoder.decode( bb, container );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest )
    {
        int start  = buffer.getPos();
        PasswordModifyRequest passwordModifyRequest = ( PasswordModifyRequest ) extendedRequest;
        
        // The new password if any
        if ( passwordModifyRequest.getNewPassword() != null )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) PasswordModifyRequestConstants.NEW_PASSWORD_TAG,
                passwordModifyRequest.getNewPassword() );
        }

        // The old password if any
        if ( passwordModifyRequest.getOldPassword() != null )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) PasswordModifyRequestConstants.OLD_PASSWORD_TAG,
                passwordModifyRequest.getOldPassword() );
        }
        
        // The user identity if any
        if ( passwordModifyRequest.getUserIdentity() != null )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) PasswordModifyRequestConstants.USER_IDENTITY_TAG,
                passwordModifyRequest.getUserIdentity() );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedResponse extendedResponse, byte[] responseValue ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( responseValue );
        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();
        container.setPasswordModifyResponse( ( PasswordModifyResponse ) extendedResponse ); 
        Asn1Decoder.decode( bb, container );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedResponse extendedResponse )
    {
        // This is a hack !!! We remove the response name from the response
        // because it has only be added to find the factory, but we don't want it
        // top be injected in the encoded PDU...
        extendedResponse.setResponseName( null );

        int start  = buffer.getPos();
        
        // The gen password
        if ( ( ( PasswordModifyResponse ) extendedResponse ).getGenPassword() != null )
        {
            BerValue.encodeOctetString( buffer, 
                ( byte ) PasswordModifyResponseConstants.GEN_PASSWORD_TAG,
                ( ( PasswordModifyResponse ) extendedResponse ).getGenPassword() );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
}
