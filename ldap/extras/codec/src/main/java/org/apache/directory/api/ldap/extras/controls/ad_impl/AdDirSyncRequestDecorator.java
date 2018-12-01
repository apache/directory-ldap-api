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
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequest;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequestImpl;
import org.apache.directory.api.util.Strings;

/**
 * A decorator around AdDirSyncRequest control. It will encode and decode this control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncRequestDecorator extends ControlDecorator<AdDirSyncRequest> implements AdDirSyncRequest
{
    /** The global length for this control */
    private int adDirSyncRequestLength;

    /** An instance of this decoder */
    private static final Asn1Decoder DECODER = new Asn1Decoder();


    /**
     * Creates a new instance of AdDirSyncRequestControlCodec.
     *
     * @param codec The LDAP Service to use
     */
    public AdDirSyncRequestDecorator( LdapApiService codec )
    {
        super( codec, new AdDirSyncRequestImpl() );
    }


    /**
     * Creates a new instance of AdDirSyncRequestDecorator.
     *
     * @param codec The LDAP Service to use
     * @param control The control to be decorated
     */
    public AdDirSyncRequestDecorator( LdapApiService codec, AdDirSyncRequest control )
    {
        super( codec, control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getParentsFirst()
    {
        return getDecorated().getParentsFirst();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setParentsFirst( int parentsFirst )
    {
        getDecorated().setParentsFirst( parentsFirst );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxAttributeCount()
    {
        return getDecorated().getMaxAttributeCount();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setMaxAttributeCount( int maxAttributeCount )
    {
        getDecorated().setMaxAttributeCount( maxAttributeCount );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getCookie()
    {
        return getDecorated().getCookie();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCookie( byte[] cookie )
    {
        // Copy the bytes
        if ( !Strings.isEmpty( cookie ) )
        {
            byte[] copy = new byte[cookie.length];
            System.arraycopy( cookie, 0, copy, 0, cookie.length );
            getDecorated().setCookie( copy );
        }
        else
        {
            getDecorated().setCookie( null );
        }
    }


    /**
     * Compute the AdDirSyncRequest length. We use the client side control.
     * <pre>
     * 0x30 L1
     * |
     * +--&gt; 0x02 0x0(1-4) nnn  (parentFirst)
     * +--&gt; 0x02 0x0(1-4) nnn  (maxAttributeCount)
     * +--&gt; 0x04 L2 xkcd!!!...     (cookie)
     * </pre>
     */
    @Override
    public int computeLength()
    {
        // the flags length
        int parentFirstLength = BerValue.getNbBytes( getParentsFirst() );
        adDirSyncRequestLength = 1 + TLV.getNbBytes( parentFirstLength ) + parentFirstLength;

        // the maxAttributeCount length
        int maxAttributeCountLength = BerValue.getNbBytes( getMaxAttributeCount() );
        adDirSyncRequestLength += 1 + TLV.getNbBytes( maxAttributeCountLength ) + maxAttributeCountLength;

        // cookie's length
        byte[] cookie = getCookie();

        if ( cookie == null )
        {
            adDirSyncRequestLength += 1 + 1;
        }
        else
        {
            adDirSyncRequestLength += 1 + TLV.getNbBytes( cookie.length ) + cookie.length;
        }

        valueLength = 1 + TLV.getNbBytes( adDirSyncRequestLength ) + adDirSyncRequestLength;

        // Call the super class to compute the global control length
        return valueLength;
    }


    /**
     * Encode the AdDirSyncRequest control. We use the client side control.
     *
     * @param buffer The encoded sink
     * @return A ByteBuffer that contains the encoded PDU
     * @throws EncoderException If anything goes wrong while encoding.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_08000_CANNOT_PUT_A_PDU_IN_NULL_BUFFER ) );
        }

        // Encode the SEQ
        buffer.put( UniversalTag.SEQUENCE.getValue() );
        buffer.put( TLV.getBytes( adDirSyncRequestLength ) );

        // Encode the parentsFirst
        BerValue.encode( buffer, getParentsFirst() );

        // Encode the MaxAttributeCount
        BerValue.encode( buffer, getMaxAttributeCount() );

        // Encode the cookie
        BerValue.encode( buffer, getCookie() );

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

                // Encode the SEQ
                buffer.put( UniversalTag.SEQUENCE.getValue() );
                buffer.put( TLV.getBytes( adDirSyncRequestLength ) );

                // Encode the parentFirst
                BerValue.encode( buffer, getParentsFirst() );

                // Encode the MaxAttributeCount
                BerValue.encode( buffer, getMaxAttributeCount() );

                // Encode the cookie
                BerValue.encode( buffer, getCookie() );

                value = buffer.array();
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
        ByteBuffer bb = ByteBuffer.wrap( controlBytes );
        AdDirSyncRequestContainer container = new AdDirSyncRequestContainer( getCodecService(), this );
        DECODER.decode( bb, container );

        return this;
    }
}
