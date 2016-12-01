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
package org.apache.directory.api.ldap.extras.extended.ads_impl.certGeneration;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationRequest;
import org.apache.directory.api.ldap.extras.extended.certGeneration.CertGenerationResponse;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for certificate generation extended request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CertGenerationRequestDecorator extends ExtendedRequestDecorator<CertGenerationRequest>
    implements CertGenerationRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( CertGenerationRequestDecorator.class );

    private CertGenerationRequest certGenerationRequest;

    /** stores the length of the request*/
    private int requestLength = 0;


    /**
     * Creates a new instance of CertGenerationRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param decoratedMessage The certificate generation request
     */
    public CertGenerationRequestDecorator( LdapApiService codec, CertGenerationRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        certGenerationRequest = decoratedMessage;
    }


    /**
     * @return The certificate generation request
     */
    public CertGenerationRequest getCertGenerationRequest()
    {
        return certGenerationRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        CertGenerationDecoder decoder = new CertGenerationDecoder();

        try
        {
            certGenerationRequest = decoder.decode( requestValue );

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
                requestValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04167 ), e );
                throw new RuntimeException( e );
            }
        }

        final byte[] copy = new byte[requestValue.length];
        System.arraycopy( requestValue, 0, copy, 0, requestValue.length );

        return copy;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CertGenerationResponse getResultResponse()
    {
        return ( CertGenerationResponse ) getDecorated().getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getTargetDN()
    {
        return getDecorated().getTargetDN();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTargetDN( String targetDN )
    {
        getDecorated().setTargetDN( targetDN );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getIssuerDN()
    {
        return getDecorated().getIssuerDN();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setIssuerDN( String issuerDN )
    {
        getDecorated().setIssuerDN( issuerDN );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSubjectDN()
    {
        return getDecorated().getSubjectDN();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSubjectDN( String subjectDN )
    {
        getDecorated().setSubjectDN( subjectDN );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getKeyAlgorithm()
    {
        return getDecorated().getKeyAlgorithm();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setKeyAlgorithm( String keyAlgorithm )
    {
        getDecorated().setKeyAlgorithm( keyAlgorithm );
    }


    /**
     * Compute the CertGenerationRequest length 
     * 
     * <pre>
     * 0x30 L1 
     *   | 
     *   +--&gt; 0x04 LL target DN
     *   +--&gt; 0x04 LL issuer DN
     *   +--&gt; 0x04 LL subject DN
     *   +--&gt; 0x04 LL key algorithm
     * </pre>
     */
    /* no qualifier */int computeLengthInternal()
    {
        int len = Strings.getBytesUtf8( certGenerationRequest.getTargetDN() ).length;
        requestLength = 1 + TLV.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( certGenerationRequest.getIssuerDN() ).length;
        requestLength += 1 + TLV.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( certGenerationRequest.getSubjectDN() ).length;
        requestLength += 1 + TLV.getNbBytes( len ) + len;

        len = Strings.getBytesUtf8( certGenerationRequest.getKeyAlgorithm() ).length;
        requestLength += 1 + TLV.getNbBytes( len ) + len;

        return 1 + TLV.getNbBytes( requestLength ) + requestLength;
    }


    /**
     * Encodes the CertGenerationRequest extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( requestLength ) );

        BerValue.encode( bb, certGenerationRequest.getTargetDN() );
        BerValue.encode( bb, certGenerationRequest.getIssuerDN() );
        BerValue.encode( bb, certGenerationRequest.getSubjectDN() );
        BerValue.encode( bb, certGenerationRequest.getKeyAlgorithm() );

        return bb;
    }
}
