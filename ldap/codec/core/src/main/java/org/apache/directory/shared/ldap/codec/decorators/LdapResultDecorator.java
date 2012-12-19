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
package org.apache.directory.shared.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.shared.ldap.codec.api.Decorator;
import org.apache.directory.shared.ldap.codec.api.LdapApiService;
import org.apache.directory.shared.ldap.codec.api.LdapEncoder;
import org.apache.directory.shared.ldap.model.message.LdapResult;
import org.apache.directory.shared.ldap.model.message.Referral;
import org.apache.directory.shared.ldap.model.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.model.name.Dn;
import org.apache.directory.shared.util.Strings;


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
     * @param decoratedLdapResult the decorated LdapResult
     */
    public LdapResultDecorator( LdapResult decoratedLdapResult )
    {
        this.decoratedLdapResult = decoratedLdapResult;
    }


    /**
     * @return The encoded Error message
     */
    public byte[] getErrorMessageBytes()
    {
        return errorMessageBytes;
    }


    /**
     * Set the encoded message's bytes
     * @param errorMessageBytes The encoded bytes
     */
    public void setErrorMessageBytes( byte[] errorMessageBytes )
    {
        this.errorMessageBytes = errorMessageBytes;
    }


    /**
     * Sets the encoded value for MatchedDn
     *
     * @param matchedDnBytes The encoded MatchedDN
     */
    public void setMatchedDnBytes( byte[] matchedDnBytes )
    {
        this.matchedDnBytes = matchedDnBytes;
    }


    /**
     * @return the encoded MatchedDN
     */
    public byte[] getMatchedDnBytes()
    {
        return matchedDnBytes;
    }


    //-------------------------------------------------------------------------
    // The LdapResult methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    public ResultCodeEnum getResultCode()
    {
        return decoratedLdapResult.getResultCode();
    }


    /**
     * {@inheritDoc}
     */
    public void setResultCode( ResultCodeEnum resultCode )
    {
        decoratedLdapResult.setResultCode( resultCode );
    }


    /**
     * {@inheritDoc}
     */
    public Dn getMatchedDn()
    {
        return decoratedLdapResult.getMatchedDn();
    }


    /**
     * {@inheritDoc}
     */
    public void setMatchedDn( Dn dn )
    {
        decoratedLdapResult.setMatchedDn( dn );
    }


    /**
     * {@inheritDoc}
     */
    public String getDiagnosticMessage()
    {
        return decoratedLdapResult.getDiagnosticMessage();
    }


    /**
     * {@inheritDoc}
     */
    public void setDiagnosticMessage( String diagnosticMessage )
    {
        decoratedLdapResult.setDiagnosticMessage( diagnosticMessage );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isReferral()
    {
        return decoratedLdapResult.isReferral();
    }


    /**
     * {@inheritDoc}
     */
    public Referral getReferral()
    {
        return decoratedLdapResult.getReferral();
    }


    /**
     * {@inheritDoc}
     */
    public void setReferral( Referral referral )
    {
        decoratedLdapResult.setReferral( referral );
    }


    /**
     * {@inheritDoc}
     */
    public String toString()
    {
        return decoratedLdapResult.toString();
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------
    /**
     * Compute the LdapResult length 
     * 
     * LdapResult : 
     *   0x0A 01 resultCode (0..80)
     *   0x04 L1 matchedDN (L1 = Length(matchedDN)) 
     *   0x04 L2 errorMessage (L2 = Length(errorMessage)) 
     *   [0x83 L3] referrals 
     *     | 
     *     +--> 0x04 L4 referral 
     *     +--> 0x04 L5 referral 
     *     +--> ... 
     *     +--> 0x04 Li referral 
     *     +--> ... 
     *     +--> 0x04 Ln referral 
     *     
     * L1 = Length(matchedDN) 
     * L2 = Length(errorMessage) 
     * L3 = n*Length(0x04) + sum(Length(L4) .. Length(Ln)) + sum(L4..Ln) 
     * L4..n = Length(0x04) + Length(Li) + Li 
     * Length(LdapResult) = Length(0x0x0A) +
     *      Length(0x01) + 1 + Length(0x04) + Length(L1) + L1 + Length(0x04) +
     *      Length(L2) + L2 + Length(0x83) + Length(L3) + L3
     */
    public int computeLength()
    {
        if ( decoratedLdapResult.isDefaultSuccess() )
        {
            // The length of a default success PDU : 0xA0 0x01 0x00 0x04 0x00 0x04 0x00
            return DEFAULT_SUCCESS.length;
        }

        int ldapResultLength = 0;

        // The result code
        ldapResultLength = 1 + 1 + BerValue.getNbBytes( getResultCode().getValue() );

        // The matchedDN length
        if ( getMatchedDn() == null )
        {
            ldapResultLength += 1 + 1;
        }
        else
        {
            byte[] matchedDNBytes = Strings.getBytesUtf8Ascii( Strings.trimLeft( getMatchedDn().getName() ) );
            ldapResultLength += 1 + TLV.getNbBytes( matchedDNBytes.length ) + matchedDNBytes.length;
            setMatchedDnBytes( matchedDNBytes );
        }

        // The errorMessage length
        byte[] errorMessageBytes = Strings.getBytesUtf8Ascii( getDiagnosticMessage() );
        ldapResultLength += 1 + TLV.getNbBytes( errorMessageBytes.length ) + errorMessageBytes.length;
        setErrorMessageBytes( errorMessageBytes );

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
            throw new EncoderException( I18n.err( I18n.ERR_04005 ) );
        }

        // The matchedDN
        BerValue.encode( buffer, getMatchedDnBytes() );

        // The error message
        BerValue.encode( buffer, getErrorMessageBytes() );

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
    public LdapResult getDecorated()
    {
        return decoratedLdapResult;
    }


    /**
     * {@inheritDoc}
     */
    public LdapApiService getCodecService()
    {
        return codec;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isDefaultSuccess()
    {
        return decoratedLdapResult.isDefaultSuccess();
    }
}
