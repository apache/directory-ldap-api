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
package org.apache.directory.api.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.Decorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * A decorator for the LdapResultResponse message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapResultDecorator implements LdapResult, Decorator<LdapResult>
{
    /** The decorated LdapResult */
    private final LdapResult decoratedLdapResult;

    /** Temporary storage for message bytes */
    private byte[] errorMessageBytes;

    /** Temporary storage of the byte[] representing the matchedDN */
    private byte[] matchedDnBytes;

    /** The codec responsible for encoding and decoding this object. */
    private LdapApiService codec;

    private static final byte[] DEFAULT_SUCCESS = new byte[]
        { 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00 };


    /**
     * Makes a LdapResult encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedLdapResult the decorated LdapResult
     */
    public LdapResultDecorator( LdapApiService codec, LdapResult decoratedLdapResult )
    {
        this.decoratedLdapResult = decoratedLdapResult;
        this.codec = codec;
    }


    //-------------------------------------------------------------------------
    // The LdapResult methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public ResultCodeEnum getResultCode()
    {
        return decoratedLdapResult.getResultCode();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResultCode( ResultCodeEnum resultCode )
    {
        decoratedLdapResult.setResultCode( resultCode );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getMatchedDn()
    {
        return decoratedLdapResult.getMatchedDn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setMatchedDn( Dn dn )
    {
        decoratedLdapResult.setMatchedDn( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getDiagnosticMessage()
    {
        return decoratedLdapResult.getDiagnosticMessage();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDiagnosticMessage( String diagnosticMessage )
    {
        decoratedLdapResult.setDiagnosticMessage( diagnosticMessage );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isReferral()
    {
        return decoratedLdapResult.isReferral();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Referral getReferral()
    {
        return decoratedLdapResult.getReferral();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setReferral( Referral referral )
    {
        decoratedLdapResult.setReferral( referral );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return decoratedLdapResult.toString();
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the LdapResult length 
     * <br>
     * LdapResult :
     * <pre> 
     *   0x0A 01 resultCode (0..80)
     *   0x04 L1 matchedDN (L1 = Length(matchedDN)) 
     *   0x04 L2 errorMessage (L2 = Length(errorMessage)) 
     *   [0x83 L3] referrals 
     *     | 
     *     +--&gt; 0x04 L4 referral 
     *     +--&gt; 0x04 L5 referral 
     *     +--&gt; ... 
     *     +--&gt; 0x04 Li referral 
     *     +--&gt; ... 
     *     +--&gt; 0x04 Ln referral 
     *     
     * L1 = Length(matchedDN) 
     * L2 = Length(errorMessage) 
     * L3 = n*Length(0x04) + sum(Length(L4) .. Length(Ln)) + sum(L4..Ln) 
     * L4..n = Length(0x04) + Length(Li) + Li 
     * Length(LdapResult) = Length(0x0x0A) +
     *      Length(0x01) + 1 + Length(0x04) + Length(L1) + L1 + Length(0x04) +
     *      Length(L2) + L2 + Length(0x83) + Length(L3) + L3
     * </pre>
     */
    @Override
    public int computeLength()
    {
        if ( decoratedLdapResult.isDefaultSuccess() )
        {
            // The length of a default success PDU : 0xA0 0x01 0x00 0x04 0x00 0x04 0x00
            return DEFAULT_SUCCESS.length;
        }

        int ldapResultLength;

        // The result code
        ldapResultLength = 1 + 1 + BerValue.getNbBytes( getResultCode().getValue() );

        // The matchedDN length
        if ( getMatchedDn() == null )
        {
            ldapResultLength += 1 + 1;
        }
        else
        {
            matchedDnBytes = Strings.getBytesUtf8Ascii( Strings.trimLeft( getMatchedDn().getName() ) );
            ldapResultLength += 1 + TLV.getNbBytes( matchedDnBytes.length ) + matchedDnBytes.length;
        }

        // The errorMessage length
        errorMessageBytes = Strings.getBytesUtf8Ascii( getDiagnosticMessage() );
        ldapResultLength += 1 + TLV.getNbBytes( errorMessageBytes.length ) + errorMessageBytes.length;

        int referralLength = LdapEncoder.computeReferralLength( getReferral() );

        if ( referralLength != 0 )
        {
            // The referrals
            ldapResultLength += 1 + TLV.getNbBytes( referralLength ) + referralLength;
        }

        return ldapResultLength;
    }


    /**
     * Encode the LdapResult message to a PDU.
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        if ( decoratedLdapResult.isDefaultSuccess() )
        {
            // The length of a default success PDU : 0xA0 0x01 0x00 0x04 0x00 0x04 0x00
            buffer.put( DEFAULT_SUCCESS );

            return buffer;
        }

        try
        {
            // The result code
            BerValue.encodeEnumerated( buffer, getResultCode().getValue() );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        // The matchedDN
        BerValue.encode( buffer, matchedDnBytes );

        // The error message
        BerValue.encode( buffer, errorMessageBytes );

        // The referrals, if any
        Referral referral = getReferral();

        if ( referral != null )
        {
            LdapEncoder.encodeReferral( buffer, referral );
        }

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapResult getDecorated()
    {
        return decoratedLdapResult;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapApiService getCodecService()
    {
        return codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDefaultSuccess()
    {
        return decoratedLdapResult.isDefaultSuccess();
    }
}
