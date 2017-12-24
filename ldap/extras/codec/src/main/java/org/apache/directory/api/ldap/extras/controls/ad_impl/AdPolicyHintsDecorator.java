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
package org.apache.directory.api.ldap.extras.controls.ad_impl;


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
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHints;
import org.apache.directory.api.ldap.extras.controls.ad.AdPolicyHintsImpl;


/**
 *  A decorator over a AdPolicyHints control.
 *   
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdPolicyHintsDecorator extends ControlDecorator<AdPolicyHints>
    implements AdPolicyHints
{
    private int seqLength;

    private static final Asn1Decoder DECODER = new Asn1Decoder();


    /**
     * Creates a new instance of AdPolicyHintsDecorator.
     *
     * @param codec The LDAP Service to use
     */
    public AdPolicyHintsDecorator( LdapApiService codec )
    {
        this( codec, new AdPolicyHintsImpl() );
    }


    /**
     * Creates a new instance of AdPolicyHintsDecorator.
     *
     * @param codec The LDAP Service to use
     * @param adPolicyHintsRequest The AdPolicyHints request to use
     */
    public AdPolicyHintsDecorator( LdapApiService codec, AdPolicyHints adPolicyHintsRequest )
    {
        super( codec, adPolicyHintsRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        seqLength = 1 + 1 + BerValue.getNbBytes( getFlags() );

        valueLength = 1 + TLV.getNbBytes( seqLength ) + seqLength;

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
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( seqLength ) );

        BerValue.encode( buffer, getFlags() );

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getValue()
    {
        if ( value == null )
        {
            try
            {
                computeLength();
                ByteBuffer buffer = ByteBuffer.allocate( valueLength );

                value = encode( buffer ).array();
            }
            catch ( Exception e )
            {
                return null;
            }
        }

        return value;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer buffer = ByteBuffer.wrap( controlBytes );
        AdPolicyHintsContainer container = new AdPolicyHintsContainer( this, getCodecService() );
        DECODER.decode( buffer, container );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getFlags()
    {
        return getDecorated().getFlags();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setFlags( int flags )
    {
        getDecorated().setFlags( flags );
    }
}