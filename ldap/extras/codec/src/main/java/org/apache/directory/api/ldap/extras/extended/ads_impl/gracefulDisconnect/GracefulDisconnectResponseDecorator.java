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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for CancelResponses.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulDisconnectResponseDecorator extends ExtendedResponseDecorator<GracefulDisconnectResponse>
    implements GracefulDisconnectResponse
{
    /** The logger. */
    private static final Logger LOG = LoggerFactory.getLogger( GracefulDisconnectResponseDecorator.class );

    /** Length of the sequence */
    private int gracefulDisconnectSequenceLength;

    /** Length of the replicated contexts */
    private int replicatedContextsLength;
    
    /** The encoded LDAP URL list */
    private List<byte[]> ldapUrlBytes;

    private GracefulDisconnectResponse gracefulDisconnectResponse;

    /**
     * Creates a new instance of CancelResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public GracefulDisconnectResponseDecorator( LdapApiService codec, GracefulDisconnectResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        gracefulDisconnectResponse = decoratedMessage;
    }

    
    // ------------------------------------------------------------------------
    // ExtendedResponse Interface Method Implementations
    // ------------------------------------------------------------------------
    /**
     * Gets the response OID specific encoded response values.
     * 
     * @return the response specific encoded response values.
     */
    @Override
    public byte[] getResponseValue()
    {
        if ( responseValue == null )
        {
            try
            {
                responseValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04164 ), e );
                throw new RuntimeException( e );
            }
        }

        return responseValue;
    }


    /**
     * Sets the response OID specific encoded response values.
     * 
     * @param responseValue the response specific encoded response values.
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        GracefulDisconnectDecoder decoder = new GracefulDisconnectDecoder();

        try
        {
            if ( responseValue != null )
            {
                decoder.decode( responseValue );
                this.responseValue = new byte[responseValue.length];
                System.arraycopy( responseValue, 0, this.responseValue, 0, responseValue.length );
            }
            else
            {
                this.responseValue = null;
            }
        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04172 ), e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getDelay()
    {
        return gracefulDisconnectResponse.getDelay();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDelay( int delay )
    {
        gracefulDisconnectResponse.setDelay( delay );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeOffline()
    {
        return gracefulDisconnectResponse.getTimeOffline();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeOffline( int timeOffline )
    {
        gracefulDisconnectResponse.setTimeOffline( timeOffline );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Referral getReplicatedContexts()
    {
        return gracefulDisconnectResponse.getReplicatedContexts();
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void addReplicatedContexts( String replicatedContext )
    {
        gracefulDisconnectResponse.getReplicatedContexts().addLdapUrl( replicatedContext );
    }


    /**
     * Compute the GracefulDisconnect length 
     * <pre>
     * 0x30 L1 
     *   | 
     *   +--> [ 0x02 0x0(1-4) [0..720] ] 
     *   +--> [ 0x80 0x0(1-3) [0..86400] ] 
     *   +--> [ 0x30 L2 
     *           | 
     *           +--> (0x04 L3 value) + ]
     * </pre>
     */
    /* no qualifier */ int computeLengthInternal()
    {
        gracefulDisconnectSequenceLength = 0;

        if ( gracefulDisconnectResponse.getTimeOffline() != 0 )
        {
            gracefulDisconnectSequenceLength += 1 + 1 + BerValue.getNbBytes( gracefulDisconnectResponse.getTimeOffline() );
        }

        if ( gracefulDisconnectResponse.getDelay() != 0 )
        {
            gracefulDisconnectSequenceLength += 1 + 1 + BerValue.getNbBytes( gracefulDisconnectResponse.getDelay() );
        }

        if ( ( gracefulDisconnectResponse.getReplicatedContexts() != null )
            && ( !gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().isEmpty() ) )
        {
            replicatedContextsLength = 0;
            
            ldapUrlBytes = new ArrayList<>( gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().size() );

            // We may have more than one reference.
            for ( String replicatedContext : gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls() )
            {
                byte[] bytes = Strings.getBytesUtf8( replicatedContext );
                ldapUrlBytes.add( bytes );
                int ldapUrlLength = bytes.length;
                replicatedContextsLength += 1 + TLV.getNbBytes( ldapUrlLength ) + ldapUrlLength;
            }

            gracefulDisconnectSequenceLength += 1 + TLV.getNbBytes( replicatedContextsLength )
                + replicatedContextsLength;
        }

        return 1 + TLV.getNbBytes( gracefulDisconnectSequenceLength ) + gracefulDisconnectSequenceLength;
    }


    /**
     * Encodes the gracefulDisconnect extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );


        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( gracefulDisconnectSequenceLength ) );

        if ( gracefulDisconnectResponse.getTimeOffline() != 0 )
        {
            BerValue.encode( bb, gracefulDisconnectResponse.getTimeOffline() );
        }

        if ( gracefulDisconnectResponse.getDelay() != 0 )
        {
            bb.put( ( byte ) GracefulActionConstants.GRACEFUL_ACTION_DELAY_TAG );
            bb.put( ( byte ) TLV.getNbBytes( gracefulDisconnectResponse.getDelay() ) );
            bb.put( BerValue.getBytes( gracefulDisconnectResponse.getDelay() ) );
        }

        if ( ( gracefulDisconnectResponse.getReplicatedContexts() != null )
            && ( !gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().isEmpty() ) )
        {
            bb.put( UniversalTag.SEQUENCE.getValue() );
            bb.put( TLV.getBytes( replicatedContextsLength ) );

            // We may have more than one reference.
            for ( byte[] replicatedContext : ldapUrlBytes )
            {
                BerValue.encode( bb, replicatedContext );
            }
        }

        return bb;
    }


    /**
     * Return a string representation of the graceful disconnect
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "Graceful Disconnect extended operation" );
        sb.append( "    TimeOffline : " ).append( gracefulDisconnectResponse.getTimeOffline() ).append( '\n' );
        sb.append( "    Delay : " ).append( gracefulDisconnectResponse.getDelay() ).append( '\n' );

        if ( ( gracefulDisconnectResponse.getReplicatedContexts() != null ) 
            && ( !gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls().isEmpty() ) )
        {
            sb.append( "    Replicated contexts :" );

            // We may have more than one reference.
            for ( String url : gracefulDisconnectResponse.getReplicatedContexts().getLdapUrls() )
            {
                sb.append( "\n        " ).append( url );
            }
        }

        return sb.toString();
    }
}
