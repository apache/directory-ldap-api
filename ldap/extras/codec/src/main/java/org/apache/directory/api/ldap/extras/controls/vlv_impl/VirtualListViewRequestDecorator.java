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
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequestImpl;


/**
 * The VirtualListView decorator
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestDecorator extends ControlDecorator<VirtualListViewRequest> implements
    VirtualListViewRequest
{
    private int vlvSeqLength;
    private int targetSeqLength;

    private static final Asn1Decoder DECODER = new Asn1Decoder();


    /**
     * Creates a new instance of VirtualListViewRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     */
    public VirtualListViewRequestDecorator( LdapApiService codec )
    {
        this( codec, new VirtualListViewRequestImpl() );
    }


    /**
     * Creates a new instance of VirtualListViewRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param vlvRequest The VLV request to use
     */
    public VirtualListViewRequestDecorator( LdapApiService codec, VirtualListViewRequest vlvRequest )
    {
        super( codec, vlvRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        vlvSeqLength = 1 + 1 + BerValue.getNbBytes( getBeforeCount() );
        vlvSeqLength += 1 + 1 + BerValue.getNbBytes( getAfterCount() );

        if ( hasOffset() )
        {
            targetSeqLength = 1 + 1 + BerValue.getNbBytes( getOffset() );
            targetSeqLength += 1 + 1 + BerValue.getNbBytes( getContentCount() );

            vlvSeqLength += 1 + 1 + targetSeqLength;
        }
        else
        {
            byte[] assertionValue = getAssertionValue();

            if ( assertionValue != null )
            {
                targetSeqLength = 1 + TLV.getNbBytes( assertionValue.length ) + assertionValue.length;
            }
            else
            {
                targetSeqLength = 1 + 1;
            }

            vlvSeqLength += targetSeqLength;
        }

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

        BerValue.encode( buffer, getBeforeCount() );
        BerValue.encode( buffer, getAfterCount() );

        if ( hasOffset() )
        {
            // The byOffset tag
            buffer.put( ( byte ) VirtualListViewerTags.BY_OFFSET_TAG.getValue() );
            buffer.put( TLV.getBytes( targetSeqLength ) );

            // The by offset values
            BerValue.encode( buffer, getOffset() );
            BerValue.encode( buffer, getContentCount() );
        }
        else
        {
            buffer.put( ( byte ) VirtualListViewerTags.ASSERTION_VALUE_TAG.getValue() );
            byte[] value = getAssertionValue();

            if ( value != null )
            {
                buffer.put( TLV.getBytes( value.length ) );

                // The by assertionValue value
                buffer.put( value );
            }
            else
            {
                buffer.put( TLV.getBytes( 0 ) );
            }
        }

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
        VirtualListViewRequestContainer container = new VirtualListViewRequestContainer( this, getCodecService() );
        DECODER.decode( buffer, container );
        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getBeforeCount()
    {
        return getDecorated().getBeforeCount();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setBeforeCount( int beforeCount )
    {
        getDecorated().setBeforeCount( beforeCount );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getAfterCount()
    {
        return getDecorated().getAfterCount();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setAfterCount( int afterCount )
    {
        getDecorated().setAfterCount( afterCount );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getOffset()
    {
        return getDecorated().getOffset();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setOffset( int offset )
    {
        getDecorated().setOffset( offset );
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


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getAssertionValue()
    {
        return getDecorated().getAssertionValue();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setAssertionValue( byte[] assertionValue )
    {
        getDecorated().setAssertionValue( assertionValue );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasOffset()
    {
        return getDecorated().hasOffset();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasAssertionValue()
    {
        return getDecorated().hasAssertionValue();
    }

}
