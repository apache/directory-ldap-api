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
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for WhoAmIResponse extended request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIResponseDecorator extends ExtendedResponseDecorator<WhoAmIResponse>
    implements WhoAmIResponse
{
    private static final Logger LOG = LoggerFactory.getLogger( WhoAmIResponseDecorator.class );

    private WhoAmIResponse whoAmIResponse;


    /**
     * Creates a new instance of WhoAmIResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public WhoAmIResponseDecorator( LdapApiService codec, WhoAmIResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        whoAmIResponse = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        WhoAmIResponseDecoder decoder = new WhoAmIResponseDecoder();

        try
        {
            if ( responseValue != null )
            {
                whoAmIResponse = decoder.decode( responseValue );

                this.responseValue = new byte[responseValue.length];
                System.arraycopy( responseValue, 0, this.responseValue, 0, responseValue.length );
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
    public byte[] getAuthzId()
    {
        return getDecorated().getAuthzId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setAuthzId( byte[] authzId )
    {
        ( ( WhoAmIResponseImpl ) getDecorated() ).setAuthzId( authzId );
    }


    /**
     * Set the userId
     */
    /* no qualifier*/void setUserId( String userId )
    {
        ( ( WhoAmIResponseImpl ) whoAmIResponse ).setUserId( userId );
    }


    /**
     * Set the DnId
     */
    /* no qualifier*/void setDn( Dn dn )
    {
        ( ( WhoAmIResponseImpl ) whoAmIResponse ).setDn( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDnAuthzId()
    {
        return whoAmIResponse.isDnAuthzId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isUserAuthzId()
    {
        return whoAmIResponse.isUserAuthzId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getAuthzIdString()
    {
        return whoAmIResponse.getAuthzIdString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getUserId()
    {
        return whoAmIResponse.getUserId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getDn()
    {
        return whoAmIResponse.getDn();
    }


    /**
     * Overload the parent's getResponseName method, as the WhoAmI response should not
     * contain the responseName.
     */
    @Override
    public String getResponseName()
    {
        return null;
    }


    /**
     * Compute the WhoAmIResponse extended operation length
     * <pre>
     * 0x04 L1 authzId
     * </pre>
     */
    /* no qualifier */int computeLengthInternal()
    {
        if ( whoAmIResponse.getAuthzId() != null )
        {
            return 1 + TLV.getNbBytes( whoAmIResponse.getAuthzId().length )
                + whoAmIResponse.getAuthzId().length;
        }
        else
        {
            return 1 + 1;
        }
    }


    /**
     * Encodes the WhoAmIResponse extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        BerValue.encode( bb, whoAmIResponse.getAuthzId() );

        return bb;
    }
}
