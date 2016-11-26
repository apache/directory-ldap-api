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
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponseImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for PasswordModifyResponse extended response.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyResponseDecorator extends ExtendedResponseDecorator<PasswordModifyResponse>
    implements PasswordModifyResponse
{
    private static final Logger LOG = LoggerFactory.getLogger( PasswordModifyResponseDecorator.class );

    private PasswordModifyResponse passwordModifyResponse;

    /** stores the length of the response*/
    private int responseLength = 0;


    /**
     * 
     * Creates a new instance of PasswordModifyResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public PasswordModifyResponseDecorator( LdapApiService codec, PasswordModifyResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        passwordModifyResponse = decoratedMessage;
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
            if ( responseValue != null )
            {
                passwordModifyResponse = decoder.decode( responseValue );

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
                responseValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04167 ), e );
                throw new RuntimeException( e );
            }
        }

        return responseValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getGenPassword()
    {
        return getDecorated().getGenPassword();
    }


    /**
     * @param genPassword the genPassword to set
     */
    public void setGenPassword( byte[] genPassword )
    {
        ( ( PasswordModifyResponseImpl ) getDecorated() ).setGenPassword( genPassword );
    }


    /**
     * Overload the parent's getResponseName method, as the pwdModify response should not
     * contain the responseName.
     */
    @Override
    public String getResponseName()
    {
        return null;
    }


    /**
     * Compute the PasswordModifyResponse extended operation length
     * <pre>
     * 0x30 L1 
     *   | 
     *  [+-- 0x80 L2 genPassword] 
     * </pre>
     */
    /* no qualifier */int computeLengthInternal()
    {
        responseLength = 0;

        if ( passwordModifyResponse.getGenPassword() != null )
        {
            int len = passwordModifyResponse.getGenPassword().length;
            responseLength = 1 + TLV.getNbBytes( len ) + len;
        }

        return 1 + TLV.getNbBytes( responseLength ) + responseLength;
    }


    /**
     * Encodes the PasswordModifyResponse extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( responseLength ) );

        if ( passwordModifyResponse.getGenPassword() != null )
        {
            byte[] userIdentity = passwordModifyResponse.getGenPassword();
            bb.put( ( byte ) PasswordModifyResponseConstants.GEN_PASSWORD_TAG );
            bb.put( TLV.getBytes( userIdentity.length ) );
            bb.put( userIdentity );
        }

        return bb;
    }
}
