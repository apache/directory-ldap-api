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
package org.apache.directory.api.ldap.extras.controls.ppolicy_impl;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyImpl;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;


/**
 * PasswordPolicy decorator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyDecorator extends ControlDecorator<PasswordPolicy> implements PasswordPolicy
{
    /** An instance of this decoder */
    private static final Asn1Decoder DECODER = new Asn1Decoder();

    // Storage for computed lengths
    private int ppolicySeqLength = 0;
    private int warningLength = 0;


    /**
     * Creates a new instance of PasswordPolicyDecorator.
     * 
     * @param codec The LDAP Service to use
     */
    public PasswordPolicyDecorator( LdapApiService codec )
    {
        super( codec, new PasswordPolicyImpl() );
    }


    /**
     * Creates a new instance of PasswordPolicyDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param hasResponse The hasResponse flag
     */
    public PasswordPolicyDecorator( LdapApiService codec, boolean hasResponse )
    {
        super( codec, new PasswordPolicyImpl( hasResponse ) );
    }


    /**
     * Creates a new instance of PasswordPolicyDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param policy The asswordPolicy to use
     */
    public PasswordPolicyDecorator( LdapApiService codec, PasswordPolicy policy )
    {
        super( codec, policy );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue( byte[] value )
    {
        if ( ( value == null ) || ( value.length <= 2 ) )
        {
            setResponse( null );
        }
        else if ( !hasResponse() )
        {
            setResponse( true );
        }

        super.setValue( value );
    }


    @Override
    public int computeLength()
    {
        // reset the length values
        valueLength = 0;
        ppolicySeqLength = 0;
        warningLength = 0;

        if ( !hasResponse() )
        {
            return 0;
        }

        if ( getResponse().getTimeBeforeExpiration() >= 0 )
        {
            int timeBeforeExpirationValueLength = BerValue.getNbBytes( getResponse().getTimeBeforeExpiration() );
            warningLength = 1 + TLV.getNbBytes( timeBeforeExpirationValueLength ) + timeBeforeExpirationValueLength;
        }
        else if ( getResponse().getGraceAuthNRemaining() >= 0 )
        {
            int graceAuthNsRemainingValueLength = BerValue.getNbBytes( getResponse().getGraceAuthNRemaining() );
            warningLength = 1 + TLV.getNbBytes( graceAuthNsRemainingValueLength ) + graceAuthNsRemainingValueLength;
        }

        if ( warningLength != 0 )
        {
            ppolicySeqLength = 1 + TLV.getNbBytes( warningLength ) + warningLength;
        }

        if ( getResponse().getPasswordPolicyError() != null )
        {
            ppolicySeqLength += 1 + 1 + 1;
        }

        valueLength = 1 + TLV.getNbBytes( ppolicySeqLength ) + ppolicySeqLength;

        return valueLength;
    }


    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( !hasResponse() )
        {
            return buffer;
        }

        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        // Encode the Sequence tag
        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( ppolicySeqLength ) );

        if ( ( getResponse().getTimeBeforeExpiration() < 0 ) && ( getResponse().getGraceAuthNRemaining() < 0 ) && (
            getResponse().getPasswordPolicyError() == null ) )
        {
            return buffer;
        }
        else
        {
            if ( warningLength > 0 )
            {
                // Encode the Warning tag
                buffer.put( ( byte ) PasswordPolicyTags.PPOLICY_WARNING_TAG.getValue() );
                buffer.put( TLV.getBytes( warningLength ) );

                if ( getResponse().getTimeBeforeExpiration() >= 0 )
                {
                    BerValue.encode(
                        buffer,
                        ( byte ) PasswordPolicyTags.TIME_BEFORE_EXPIRATION_TAG.getValue(),
                        getResponse().getTimeBeforeExpiration() );
                }
                else if ( getResponse().getGraceAuthNRemaining() >= 0 )
                {
                    BerValue.encode(
                        buffer,
                        ( byte ) PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG.getValue(),
                        getResponse().getGraceAuthNRemaining() );
                }
            }

            if ( getResponse().getPasswordPolicyError() != null )
            {
                BerValue.encode(
                    buffer,
                    ( byte ) PasswordPolicyTags.PPOLICY_ERROR_TAG.getValue(),
                    getResponse().getPasswordPolicyError().getValue() );
            }
        }

        return buffer;
    }


    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "  PasswordPolicyResponse control :\n" );
        sb.append( "   oid          : '" ).append( getOid() ).append( '\n' );

        if ( hasResponse() && getResponse().getTimeBeforeExpiration() >= 0 )
        {
            sb.append( "   timeBeforeExpiration          : '" ).append( getResponse().getTimeBeforeExpiration() )
                .append( '\n' );
        }
        else if ( hasResponse() && getResponse().getGraceAuthNRemaining() >= 0 )
        {
            sb.append( "   graceAuthNsRemaining          : '" ).append( getResponse().getGraceAuthNRemaining() )
                .append( '\n' );
        }

        if ( hasResponse() && getResponse().getPasswordPolicyError() != null )
        {
            sb.append( "   ppolicyError          : '" ).append( getResponse().getPasswordPolicyError().toString() )
                .append( '\n' );
        }

        return sb.toString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        if ( !hasResponse() )
        {
            return this;
        }

        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        PasswordPolicyContainer container = new PasswordPolicyContainer( getCodecService(), this );
        DECODER.decode( bb, container );
        return this;
    }


    /**
     *
     * {@inheritDoc}
     */
    @Override
    public boolean hasResponse()
    {
        return getDecorated().hasResponse();
    }


    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void setResponse( PasswordPolicyResponse response )
    {
        getDecorated().setResponse( response );
    }


    /**
     *
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyResponse setResponse( boolean hasResponse )
    {
        return getDecorated().setResponse( hasResponse );
    }


    /**
     *
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyResponse getResponse()
    {
        return getDecorated().getResponse();
    }
}
