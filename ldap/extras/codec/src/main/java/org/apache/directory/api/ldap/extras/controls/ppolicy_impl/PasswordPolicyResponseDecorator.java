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
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyErrorEnum;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponse;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicyResponseImpl;


/**
 * PasswordPolicyResponse decorator.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordPolicyResponseDecorator extends ControlDecorator<PasswordPolicyResponse> implements PasswordPolicyResponse
{
    /** An instance of this decoder */
    private static final Asn1Decoder DECODER = new Asn1Decoder();

    // Storage for computed lengths
    private int ppolicySeqLength = 0;
    private int warningLength = 0;


    /**
     * Creates a new instance of PasswordPolicyResponseDecorator.
     * 
     * @param codec The LDAP Service to use
     */
    public PasswordPolicyResponseDecorator( LdapApiService codec )
    {
        super( codec, new PasswordPolicyResponseImpl() );
    }


    /**
     * Creates a new instance of PasswordPolicyDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param policy The asswordPolicy to use
     */
    public PasswordPolicyResponseDecorator( LdapApiService codec, PasswordPolicyResponse policy )
    {
        super( codec, policy );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setValue( byte[] value )
    {
        super.setValue( value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        // reset the length values
        valueLength = 0;
        ppolicySeqLength = 0;
        warningLength = 0;

        if ( getDecorated().getTimeBeforeExpiration() >= 0 )
        {
            int timeBeforeExpirationValueLength = BerValue.getNbBytes( getDecorated().getTimeBeforeExpiration() );
            warningLength = 1 + TLV.getNbBytes( timeBeforeExpirationValueLength ) + timeBeforeExpirationValueLength;
        }
        else if ( getDecorated().getGraceAuthNRemaining() >= 0 )
        {
            int graceAuthNsRemainingValueLength = BerValue.getNbBytes( getDecorated().getGraceAuthNRemaining() );
            warningLength = 1 + TLV.getNbBytes( graceAuthNsRemainingValueLength ) + graceAuthNsRemainingValueLength;
        }

        if ( warningLength != 0 )
        {
            ppolicySeqLength = 1 + TLV.getNbBytes( warningLength ) + warningLength;
        }

        if ( getDecorated().getPasswordPolicyError() != null )
        {
            ppolicySeqLength += 1 + 1 + 1;
        }

        valueLength = 1 + TLV.getNbBytes( ppolicySeqLength ) + ppolicySeqLength;

        return valueLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_08000_CANNOT_PUT_A_PDU_IN_NULL_BUFFER ) );
        }

        // Encode the Sequence tag
        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( ppolicySeqLength ) );

        if ( ( getDecorated().getTimeBeforeExpiration() < 0 ) && ( getDecorated().getGraceAuthNRemaining() < 0 ) && (
            getDecorated().getPasswordPolicyError() == null ) )
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

                if ( getDecorated().getTimeBeforeExpiration() >= 0 )
                {
                    BerValue.encode(
                        buffer,
                        ( byte ) PasswordPolicyTags.TIME_BEFORE_EXPIRATION_TAG.getValue(),
                        getDecorated().getTimeBeforeExpiration() );
                }
                else if ( getDecorated().getGraceAuthNRemaining() >= 0 )
                {
                    BerValue.encode(
                        buffer,
                        ( byte ) PasswordPolicyTags.GRACE_AUTHNS_REMAINING_TAG.getValue(),
                        getDecorated().getGraceAuthNRemaining() );
                }
            }

            if ( getDecorated().getPasswordPolicyError() != null )
            {
                BerValue.encode(
                    buffer,
                    ( byte ) PasswordPolicyTags.PPOLICY_ERROR_TAG.getValue(),
                    getDecorated().getPasswordPolicyError().getValue() );
            }
        }

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "  PasswordPolicyResponse control :\n" );
        sb.append( "   oid          : '" ).append( getOid() ).append( '\n' );

        if ( getDecorated().getTimeBeforeExpiration() >= 0 )
        {
            sb.append( "   timeBeforeExpiration          : '" ).append( getDecorated().getTimeBeforeExpiration() )
                .append( '\n' );
        }
        else if ( getDecorated().getGraceAuthNRemaining() >= 0 )
        {
            sb.append( "   graceAuthNsRemaining          : '" ).append( getDecorated().getGraceAuthNRemaining() )
                .append( '\n' );
        }

        if ( getDecorated().getPasswordPolicyError() != null )
        {
            sb.append( "   ppolicyError          : '" ).append( getDecorated().getPasswordPolicyError().toString() )
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
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        PasswordPolicyResponseContainer container = new PasswordPolicyResponseContainer( getCodecService(), getDecorated() );
        DECODER.decode( bb, container );
        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeBeforeExpiration()
    {
        return getDecorated().getTimeBeforeExpiration();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeBeforeExpiration( int timeBeforeExpiration )
    {
        getDecorated().setTimeBeforeExpiration( timeBeforeExpiration );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getGraceAuthNRemaining()
    {
        return getDecorated().getGraceAuthNRemaining();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setGraceAuthNRemaining( int graceAuthNRemaining )
    {
        getDecorated().setGraceAuthNRemaining( graceAuthNRemaining );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyErrorEnum getPasswordPolicyError()
    {
        return getDecorated().getPasswordPolicyError();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setPasswordPolicyError( PasswordPolicyErrorEnum ppolicyError )
    {
        getDecorated().setPasswordPolicyError( ppolicyError );
    }
}
