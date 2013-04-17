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
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.PwdModifyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for PasswordModifyResponse extended request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyResponseDecorator extends ExtendedResponseDecorator<PwdModifyResponse>
    implements PwdModifyResponse
{
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyResponseDecorator.class );

    private PasswordModifyResponse passwordModifyResponse;


    public PasswordModifyResponseDecorator( LdapApiService codec, PwdModifyResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        passwordModifyResponse = new PasswordModifyResponse( decoratedMessage );
    }


    public PasswordModifyResponse getPasswordModifyResponse()
    {
        return passwordModifyResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        PasswordModifyResponseDecoder decoder = new PasswordModifyResponseDecoder();

        try
        {
            passwordModifyResponse = ( PasswordModifyResponse ) decoder.decode( responseValue );

            if ( responseValue != null )
            {
                this.responseValue = new byte[responseValue.length];
                System.arraycopy( responseValue, 0, this.responseValue, 0, responseValue.length );
            }
            else
            {
                this.responseValue = null;
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
    public byte[] getResponseValue()
    {
        if ( responseValue == null )
        {
            try
            {
                responseValue = passwordModifyResponse.encode().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04167 ), e );
                throw new RuntimeException( e );
            }
        }

        if ( responseValue == null )
        {
            return null;
        }

        final byte[] copy = new byte[responseValue.length];
        System.arraycopy( responseValue, 0, copy, 0, responseValue.length );

        return copy;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getGenPassword()
    {
        return getDecorated().getGenPassword();
    }
}
