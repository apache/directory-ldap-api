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
package org.apache.directory.api.ldap.codec.controls.sort;


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
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.SortResponseControlImpl;
import org.apache.directory.api.ldap.model.message.controls.SortResultCode;
import org.apache.directory.api.util.Strings;


/**
 * Decorator class for SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortResponseDecorator extends ControlDecorator<SortResponse> implements SortResponse
{
    private static final Asn1Decoder DECODER = new Asn1Decoder();

    private int sortRespLen = 0;


    /**
     * Creates a new instance of SortResponseDecorator.
     *
     * @param codec the LDAP codec
     */
    public SortResponseDecorator( LdapApiService codec )
    {
        super( codec, new SortResponseControlImpl() );
    }


    /**
     * Creates a new instance of SortResponseDecorator.
     *
     * @param codec the LDAP codec
     * @param control the sort response control
     */
    public SortResponseDecorator( LdapApiService codec, SortResponse control )
    {
        super( codec, control );
    }


    /**
     * @return the control length.
     */
    @Override
    public int computeLength()
    {
        sortRespLen = 0;
        valueLength = 0;

        // result code value
        sortRespLen += 1 + 1 + 1;

        if ( getAttributeName() != null )
        {
            byte[] data = Strings.getBytesUtf8( getAttributeName() );
            sortRespLen += 1 + TLV.getNbBytes( data.length ) + data.length;
        }

        valueLength = 1 + TLV.getNbBytes( sortRespLen ) + sortRespLen;

        return valueLength;
    }


    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04023 ) );
        }

        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( sortRespLen ) );

        BerValue.encodeEnumerated( buffer, getSortResult().getVal() );

        if ( getAttributeName() != null )
        {
            BerValue.encode( buffer, getAttributeName() );
        }

        return buffer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Object decode( byte[] controlBytes ) throws DecoderException
    {
        ByteBuffer buffer = ByteBuffer.wrap( controlBytes );
        SortResponseContainer container = new SortResponseContainer( getCodecService(), this );
        DECODER.decode( buffer, container );
        return this;
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


    @Override
    public void setSortResult( SortResultCode result )
    {
        getDecorated().setSortResult( result );
    }


    @Override
    public SortResultCode getSortResult()
    {
        return getDecorated().getSortResult();
    }


    @Override
    public void setAttributeName( String attributeName )
    {
        getDecorated().setAttributeName( attributeName );
    }


    @Override
    public String getAttributeName()
    {
        return getDecorated().getAttributeName();
    }

}
