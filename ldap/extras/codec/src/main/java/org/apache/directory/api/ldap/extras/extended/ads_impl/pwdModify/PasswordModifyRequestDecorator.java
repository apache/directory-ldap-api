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
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for PasswordModifyRequest extended request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyRequestDecorator extends ExtendedRequestDecorator<PasswordModifyRequest>
    implements PasswordModifyRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyRequestDecorator.class );

    /** The internal PasswordModifyRequest */
    private PasswordModifyRequest passwordModifyRequest;

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * Create a new decorator instance 
     * @param codec The codec service
     * @param decoratedMessage The decorated PwdModifyRequest
     */
    public PasswordModifyRequestDecorator( LdapApiService codec, PasswordModifyRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        passwordModifyRequest = decoratedMessage;
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
            if ( requestValue != null )
            {
                passwordModifyRequest = decoder.decode( requestValue );

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
                requestValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04167 ), e );
                throw new RuntimeException( e );
            }
        }

        return requestValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyResponse getResultResponse()
    {
        return ( PasswordModifyResponse ) passwordModifyRequest.getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getUserIdentity()
    {
        return passwordModifyRequest.getUserIdentity();
    }


    /**
     * @param userIdentity the userIdentity to set
     */
    @Override
    public void setUserIdentity( byte[] userIdentity )
    {
        passwordModifyRequest.setUserIdentity( userIdentity );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getOldPassword()
    {
        return passwordModifyRequest.getOldPassword();
    }


    /**
     * @param oldPassword the oldPassword to set
     */
    @Override
    public void setOldPassword( byte[] oldPassword )
    {
        passwordModifyRequest.setOldPassword( oldPassword );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getNewPassword()
    {
        return passwordModifyRequest.getNewPassword();
    }


    /**
     * @param newPassword the newPassword to set
     */
    @Override
    public void setNewPassword( byte[] newPassword )
    {
        passwordModifyRequest.setNewPassword( newPassword );
    }


    /**
     * Compute the PasswordModifyRequest extended operation length
     * <pre>
     * 0x30 L1 
     *   | 
     *  [+-- 0x80 L2 userIdentity] 
     *  [+-- 0x81 L3 oldPassword] 
     *  [+-- 0x82 L4 newPassword] 
     * </pre>
     */
    /* No qualifier */int computeLengthInternal()
    {
        requestLength = 0;

        if ( passwordModifyRequest.getUserIdentity() != null )
        {
            int len = passwordModifyRequest.getUserIdentity().length;
            requestLength = 1 + TLV.getNbBytes( len ) + len;
        }

        if ( passwordModifyRequest.getOldPassword() != null )
        {
            int len = passwordModifyRequest.getOldPassword().length;
            requestLength += 1 + TLV.getNbBytes( len ) + len;
        }

        if ( passwordModifyRequest.getNewPassword() != null )
        {
            int len = passwordModifyRequest.getNewPassword().length;
            requestLength += 1 + TLV.getNbBytes( len ) + len;
        }

        return 1 + TLV.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * Encodes the PasswordModifyRequest extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* No qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( requestLength ) );

        if ( passwordModifyRequest.getUserIdentity() != null )
        {
            byte[] userIdentity = passwordModifyRequest.getUserIdentity();
            bb.put( ( byte ) PasswordModifyRequestConstants.USER_IDENTITY_TAG );
            bb.put( TLV.getBytes( userIdentity.length ) );
            bb.put( userIdentity );
        }

        if ( passwordModifyRequest.getOldPassword() != null )
        {
            byte[] oldPassword = passwordModifyRequest.getOldPassword();
            bb.put( ( byte ) PasswordModifyRequestConstants.OLD_PASSWORD_TAG );
            bb.put( TLV.getBytes( oldPassword.length ) );
            bb.put( oldPassword );
        }

        if ( passwordModifyRequest.getNewPassword() != null )
        {
            byte[] newPassword = passwordModifyRequest.getNewPassword();
            bb.put( ( byte ) PasswordModifyRequestConstants.NEW_PASSWORD_TAG );
            bb.put( TLV.getBytes( newPassword.length ) );
            bb.put( newPassword );
        }

        return bb;
    }
}
