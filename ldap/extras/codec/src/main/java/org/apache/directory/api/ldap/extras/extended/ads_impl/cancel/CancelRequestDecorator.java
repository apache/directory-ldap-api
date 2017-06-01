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
package org.apache.directory.api.ldap.extras.extended.ads_impl.cancel;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for CancelRequests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CancelRequestDecorator extends ExtendedRequestDecorator<CancelRequest> implements
    CancelRequest, Asn1Object
{
    private static final Logger LOG = LoggerFactory.getLogger( CancelRequestDecorator.class );

    /** The Id of the the message to cancel */
    private CancelRequest cancelRequest;

    /** Length of the sequence */
    private int cancelSequenceLength;


    /**
     * Creates a new instance of CancelRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param decoratedMessage The canceled request
     */
    public CancelRequestDecorator( LdapApiService codec, CancelRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        cancelRequest = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getCancelId()
    {
        return cancelRequest.getCancelId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCancelId( int cancelId )
    {
        if ( cancelId == cancelRequest.getCancelId() )
        {
            return;
        }

        this.requestValue = null;
        cancelRequest.setCancelId( cancelId );
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
                LOG.error( I18n.err( I18n.ERR_04164 ), e );
                throw new RuntimeException( e );
            }
        }

        return requestValue;
    }


    /**
     * Sets the extended request's <b>requestValue</b> portion of the PDU.
     *
     * @param requestValue byte array of data encapsulating ext. req. parameters
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        CancelDecoder decoder = new CancelDecoder();

        try
        {
            if ( requestValue != null )
            {
                CancelRequest cancel = decoder.decode( requestValue );
                cancelRequest.setCancelId( cancel.getCancelId() );

                this.requestValue = new byte[requestValue.length];
                System.arraycopy( requestValue, 0, this.requestValue, 0, requestValue.length );
            }
            else
            {
                this.requestValue = null;
                cancelRequest.setCancelId( 0 );
            }

        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04165 ), e );
            throw new RuntimeException( e );
        }
    }


    /**
     * Compute the Cancel length 
     * <pre>
     * 0x30 L1 
     *   | 
     *   +--&gt; 0x02 0x0(1-4) [0..2^31-1]
     * </pre> 
     */
    /* no qualifier */int computeLengthInternal()
    {
        // The messageId length
        cancelSequenceLength = 1 + 1 + BerValue.getNbBytes( cancelRequest.getCancelId() );

        // Add the sequence and the length
        return 1 + 1 + cancelSequenceLength;
    }


    /**
     * Encodes the cancel extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        // The sequence
        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( cancelSequenceLength ) );

        // The messageId
        BerValue.encode( bb, cancelRequest.getCancelId() );

        return bb;
    }
}
