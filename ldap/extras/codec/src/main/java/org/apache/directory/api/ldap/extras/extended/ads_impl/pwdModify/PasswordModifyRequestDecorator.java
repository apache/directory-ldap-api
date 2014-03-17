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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PwdModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PwdModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PwdModifyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for PasswordModifyRequest extended request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyRequestDecorator
    extends ExtendedRequestDecorator<PwdModifyRequest, PwdModifyResponse>
    implements PwdModifyRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyRequestDecorator.class );

    /** The internal PasswordModifyRequest */
    private PasswordModifyRequest passwordModifyRequest;


    /**
     * Create a new decorator instance 
     * @param codec The codec service
     * @param decoratedMessage The decorated PwdModifyRequest
     */
    public PasswordModifyRequestDecorator( LdapApiService codec, PwdModifyRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        passwordModifyRequest = new PasswordModifyRequest( decoratedMessage );
    }


    /**
     * @return The ASN1 object containing the PwdModifyRequest instance
     */
    public PasswordModifyRequest getPasswordModifyRequest()
    {
        return passwordModifyRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        PasswordModifyRequestDecoder decoder = new PasswordModifyRequestDecoder();

        try
        {
            passwordModifyRequest = ( PasswordModifyRequest ) decoder.decode( requestValue );
            ( ( PwdModifyRequestImpl ) getDecorated() ).setUserIdentity( passwordModifyRequest.getPwdModifyRequest()
                .getUserIdentity() );
            ( ( PwdModifyRequestImpl ) getDecorated() ).setOldPassword( passwordModifyRequest.getPwdModifyRequest()
                .getOldPassword() );
            ( ( PwdModifyRequestImpl ) getDecorated() ).setNewPassword( passwordModifyRequest.getPwdModifyRequest()
                .getNewPassword() );

            if ( requestValue != null )
            {
                this.requestValue = new byte[requestValue.length];
                System.arraycopy( requestValue, 0, this.requestValue, 0, requestValue.length );
            }
            else
            {
                this.requestValue = null;
            }
        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04165 ), e );
            throw new RuntimeException( e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getRequestValue()
    {
        if ( requestValue == null )
        {
            try
            {
                requestValue = passwordModifyRequest.encode().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04167 ), e );
                throw new RuntimeException( e );
            }
        }

        if ( requestValue == null )
        {
            return null;
        }

        final byte[] copy = new byte[requestValue.length];
        System.arraycopy( requestValue, 0, copy, 0, requestValue.length );
        return copy;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PwdModifyResponse getResultResponse()
    {
        return getDecorated().getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getUserIdentity()
    {
        return ( ( PwdModifyRequestImpl ) getDecorated() ).getUserIdentity();
    }


    /**
     * @param userIdentity the userIdentity to set
     */
    public void setUserIdentity( byte[] userIdentity )
    {
        ( ( PwdModifyRequestImpl ) getDecorated() ).setUserIdentity( userIdentity );
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getOldPassword()
    {
        return ( ( PwdModifyRequestImpl ) getDecorated() ).getOldPassword();
    }


    /**
     * @param oldPassword the oldPassword to set
     */
    public void setOldPassword( byte[] oldPassword )
    {
        ( ( PwdModifyRequestImpl ) getDecorated() ).setOldPassword( oldPassword );
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getNewPassword()
    {
        return ( ( PwdModifyRequestImpl ) getDecorated() ).getNewPassword();
    }


    /**
     * @param newPassword the newPassword to set
     */
    public void setNewPassword( byte[] newPassword )
    {
        ( ( PwdModifyRequestImpl ) getDecorated() ).setNewPassword( newPassword );
    }
}
