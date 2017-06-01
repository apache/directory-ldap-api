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

package org.apache.directory.api.ldap.extras.controls.vlv_impl;


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
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponseImpl;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResultCode;


/**
 * The VirtualListView response decorator
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewResponseDecorator extends ControlDecorator<VirtualListViewResponse> implements
    VirtualListViewResponse
{
    private int vlvSeqLength;

    private static final Asn1Decoder DECODER = new Asn1Decoder();


    /**
     * Create a new SyncRequestValueDecorator instance 
     * 
     * @param codec The LDAP API service to use
     */
    public VirtualListViewResponseDecorator( LdapApiService codec )
    {
        this( codec, new VirtualListViewResponseImpl() );
    }


    /**
     * Create a new SyncRequestValueDecorator instance 
     * 
     * @param codec The LDAP API service to use
     * @param vlvRequest The decorated VLV request
     */
    public VirtualListViewResponseDecorator( LdapApiService codec, VirtualListViewResponse vlvRequest )
    {
        super( codec, vlvRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        vlvSeqLength = 1 + 1 + BerValue.getNbBytes( getTargetPosition() );
        vlvSeqLength += 1 + 1 + BerValue.getNbBytes( getContentCount() );

        // result code : always one byte long
        vlvSeqLength += 1 + 1 + 1;

        if ( getContextId() != null )
        {
            vlvSeqLength += 1 + TLV.getNbBytes( getContextId().length ) + getContextId().length;
        }

        valueLength = 1 + TLV.getNbBytes( vlvSeqLength ) + vlvSeqLength;

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
        buffer.put( TLV.getBytes( vlvSeqLength ) );

        BerValue.encode( buffer, getTargetPosition() );
        BerValue.encode( buffer, getContentCount() );

        BerValue.encodeEnumerated( buffer, getVirtualListViewResult().getValue() );

        if ( getContextId() != null )
        {
            BerValue.encode( buffer, getContextId() );
        }

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
        VirtualListViewResponseContainer container = new VirtualListViewResponseContainer( this, getCodecService() );
        DECODER.decode( buffer, container );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTargetPosition()
    {
        return getDecorated().getTargetPosition();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTargetPosition( int targetPosition )
    {
        getDecorated().setTargetPosition( targetPosition );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getContentCount()
    {
        return getDecorated().getContentCount();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setContentCount( int contentCount )
    {
        getDecorated().setContentCount( contentCount );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public VirtualListViewResultCode getVirtualListViewResult()
    {
        return getDecorated().getVirtualListViewResult();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setVirtualListViewResult( VirtualListViewResultCode virtualListViewResult )
    {
        getDecorated().setVirtualListViewResult( virtualListViewResult );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getContextId()
    {
        return getDecorated().getContextId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setContextId( byte[] contextId )
    {
        getDecorated().setContextId( contextId );
    }

}
