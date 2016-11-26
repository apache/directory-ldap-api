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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulActionConstants;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for GracefulShutdownRequests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulShutdownRequestDecorator extends ExtendedRequestDecorator<GracefulShutdownRequest>
    implements GracefulShutdownRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( GracefulShutdownRequestDecorator.class );

    /** Length of the sequence */
    private int gracefulSequenceLength;

    private GracefulShutdownRequest gracefulShutdownRequest;


    /**
     * Creates a new instance of GracefulShutdownRequestDecorator.
     *
     * @param codec The LDAP Service to use
     * @param decoratedMessage The GracefulShutdownRequest control to decorate
     */
    public GracefulShutdownRequestDecorator( LdapApiService codec, GracefulShutdownRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        gracefulShutdownRequest = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        GracefulShutdownDecoder decoder = new GracefulShutdownDecoder();

        try
        {
            if ( requestValue != null )
            {
                gracefulShutdownRequest = decoder.decode( requestValue );

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
                LOG.error( I18n.err( I18n.ERR_04164 ), e );
                throw new RuntimeException( e );
            }
        }

        return requestValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getDelay()
    {
        return getDecorated().getDelay();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDelay( int delay )
    {
        getDecorated().setDelay( delay );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeOffline()
    {
        return getDecorated().getTimeOffline();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeOffline( int timeOffline )
    {
        getDecorated().setTimeOffline( timeOffline );
    }


    /**
     * Compute the GracefulShutdown length 
     * 
     * <pre>
     * 0x30 L1 
     *   | 
     *   +--&gt; [0x02 0x0(1-4) [0..720] ] 
     *   +--&gt; [0x80 0x0(1-3) [0..86400] ] 
     * </pre>  
     * L1 will always be &lt; 11.
     */
    /* no qualifier */int computeLengthInternal()
    {
        int gracefulLength = 1 + 1;
        gracefulSequenceLength = 0;

        if ( gracefulShutdownRequest.getTimeOffline() != 0 )
        {
            gracefulSequenceLength += 1 + 1 + BerValue.getNbBytes( gracefulShutdownRequest.getTimeOffline() );
        }

        if ( gracefulShutdownRequest.getDelay() != 0 )
        {
            gracefulSequenceLength += 1 + 1 + BerValue.getNbBytes( gracefulShutdownRequest.getDelay() );
        }

        return gracefulLength + gracefulSequenceLength;
    }


    /**
     * Encodes the gracefulShutdown extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( gracefulSequenceLength ) );

        if ( gracefulShutdownRequest.getTimeOffline() != 0 )
        {
            BerValue.encode( bb, gracefulShutdownRequest.getTimeOffline() );
        }

        if ( gracefulShutdownRequest.getDelay() != 0 )
        {
            bb.put( ( byte ) GracefulActionConstants.GRACEFUL_ACTION_DELAY_TAG );
            bb.put( ( byte ) BerValue.getNbBytes( gracefulShutdownRequest.getDelay() ) );
            bb.put( BerValue.getBytes( gracefulShutdownRequest.getDelay() ) );
        }
        return bb;
    }


    /**
     * Return a string representation of the graceful shutdown
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "Graceful Shutdown extended operation" );
        sb.append( "    TimeOffline : " ).append( gracefulShutdownRequest.getTimeOffline() ).append( '\n' );
        sb.append( "    Delay : " ).append( gracefulShutdownRequest.getDelay() ).append( '\n' );

        return sb.toString();
    }
}
