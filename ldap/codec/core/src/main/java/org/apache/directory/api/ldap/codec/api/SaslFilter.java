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
package org.apache.directory.api.ldap.codec.api;


import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;

import org.apache.directory.api.ldap.model.constants.SaslQoP;
import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.DefaultWriteRequest;
import org.apache.mina.core.write.WriteRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link IoFilterAdapter} that handles integrity and confidentiality protection
 * for a SASL bound session.  The SaslFilter must be constructed with a SASL
 * context that has completed SASL negotiation.  Some SASL mechanisms, such as
 * CRAM-MD5, only support authentication and thus do not need this filter.  DIGEST-MD5
 * and GSSAPI do support message integrity and confidentiality and, therefore,
 * do need this filter.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SaslFilter extends IoFilterAdapter
{
    private static final Logger LOG = LoggerFactory.getLogger( SaslFilter.class );

    /**
     * A session attribute key that makes next one write request bypass
     * this filter (not adding a security layer).  This is a marker attribute,
     * which means that you can put whatever as its value. ({@link Boolean#TRUE}
     * is preferred.)  The attribute is automatically removed from the session
     * attribute map as soon as {@link IoSession#write(Object)} is invoked,
     * and therefore should be put again if you want to make more messages
     * bypass this filter.
     */
    public static final String DISABLE_SECURITY_LAYER_ONCE = SaslFilter.class.getName() + ".DisableSecurityLayerOnce";

    /**
     * A session attribute key that holds the received bytes of partially received
     * SASL message.
     */
    public static final String BYTES = SaslFilter.class.getName() + ".Buffer";

    /**
     * A session attribute key that holds the offset of partially received
     * SASL message.
     */
    public static final String OFFSET = SaslFilter.class.getName() + ".Offset";

    /** The SASL client, only set if the filter is used at the client side. */
    private final SaslClient saslClient;

    /** The SASL server, only set if the filter is used at the server side. */
    private final SaslServer saslServer;

    /** True if a security layer has been negotiated */
    private boolean hasSecurityLayer;

    /** The negotiated max buffer size */
    private int maxBufferSize;

    /**
     * Creates a new instance of SaslFilter.  The SaslFilter must be constructed
     * with a SASL client that has completed SASL negotiation.  The SASL client
     * will be used to provide message integrity and, optionally, message
     * confidentiality.
     *
     * @param saslClient The initialized SASL client.
     */
    public SaslFilter( SaslClient saslClient )
    {
        if ( saslClient == null )
        {
            throw new IllegalArgumentException();
        }

        this.saslServer = null;
        this.saslClient = saslClient;
        initHasSecurityLayer( ( String ) saslClient.getNegotiatedProperty( Sasl.QOP ) );
        initMaxBuffer( ( String ) saslClient.getNegotiatedProperty( Sasl.MAX_BUFFER ) );
    }


    /**
     * Creates a new instance of SaslFilter.  The SaslFilter must be constructed
     * with a SASL server that has completed SASL negotiation.  The SASL server
     * will be used to provide message integrity and, optionally, message
     * confidentiality.
     *
     * @param saslClient The initialized SASL server.
     */
    public SaslFilter( SaslServer saslServer )
    {
        if ( saslServer == null )
        {
            throw new IllegalArgumentException();
        }

        this.saslClient = null;
        this.saslServer = saslServer;
        initHasSecurityLayer( ( String ) saslServer.getNegotiatedProperty( Sasl.QOP ) );
        initMaxBuffer( ( String ) saslServer.getNegotiatedProperty( Sasl.MAX_BUFFER ) );
    }


    private void initHasSecurityLayer( String qop )
    {
        this.hasSecurityLayer = ( qop != null && ( qop.equals( SaslQoP.AUTH_INT.getValue() ) || qop
            .equals( SaslQoP.AUTH_CONF.getValue() ) ) );
    }


    private void initMaxBuffer( String maxBuffer )
    {
        this.maxBufferSize = maxBuffer != null ? Integer.parseInt( maxBuffer ) : 65536;
    }


    @Override
    public synchronized void messageReceived( NextFilter nextFilter, IoSession session, Object message )
        throws SaslException
    {
        LOG.debug( "Message received:  {}", message );

        if ( !hasSecurityLayer )
        {
            LOG.debug( "Will not use SASL on received message." );
            nextFilter.messageReceived( session, message );
            return;
        }

        /*
         * Unwrap the data for mechanisms that support QoP (DIGEST-MD5, GSSAPI).
         */
        IoBuffer buf = ( IoBuffer ) message;
        while ( buf.hasRemaining() )
        {
            /*
             * Check for a previously received partial SASL message which is stored in the session.
             * Otherwise read the first 4 bytes which is the length and allocate the bytes.
             * Ensure the buffer size doesn't exceed the negotiated max buffer size.
             */
            byte[] bytes = ( byte[] ) session.getAttribute( BYTES, null );
            int offset = ( int ) session.getAttribute( OFFSET, -1 );
            if ( bytes == null )
            {
                int bufferSize = buf.getInt();
                if ( bufferSize > maxBufferSize )
                {
                    throw new IllegalStateException(
                        bufferSize + " exceeds the negotiated receive buffer size limit: " + maxBufferSize );
                }
                bytes = new byte[bufferSize];
                offset = 0;
            }

            /*
             * Get the buffer as bytes. Handle the case that only a part of the SASL message was received.
             */
            int length = Math.min( bytes.length - offset, buf.remaining() );
            buf.get( bytes, offset, length );

            /*
             * Check if the full SASL message was received. If not store the partially received data in
             * the session so it can be resumed when the next message is received.
             */
            offset += length;
            if ( offset < bytes.length )
            {
                LOG.debug( "Partial SASL message received:  {}/{}", offset, bytes.length );
                session.setAttribute( BYTES, bytes );
                session.setAttribute( OFFSET, offset );
                break;
            }

            /*
             * Unwrap the SASL message and forward it to the next filter.
             */
            LOG.debug( "Will use SASL to unwrap received message of length:  {}", bytes.length );
            byte[] token = unwrap( bytes, 0, bytes.length );
            nextFilter.messageReceived( session, IoBuffer.wrap( token ) );

            /*
             * Finally clear the session attributes.
             */
            session.removeAttribute( BYTES );
            session.removeAttribute( OFFSET );
        }
    }


    @Override
    public synchronized void filterWrite( NextFilter nextFilter, IoSession session, WriteRequest writeRequest )
        throws SaslException
    {
        LOG.debug( "Filtering write request:  {}", writeRequest );

        /*
         * Check if security layer processing should be disabled once.
         */
        if ( session.containsAttribute( DISABLE_SECURITY_LAYER_ONCE ) )
        {
            // Remove the marker attribute because it is temporary.
            LOG.debug( "Disabling SaslFilter once; will not use SASL on write request." );
            session.removeAttribute( DISABLE_SECURITY_LAYER_ONCE );
            nextFilter.filterWrite( session, writeRequest );
            return;
        }

        if ( !hasSecurityLayer )
        {
            LOG.debug( "Will not use SASL on write request." );
            nextFilter.filterWrite( session, writeRequest );
            return;
        }

        /*
         * Wrap the data for mechanisms that support QoP (DIGEST-MD5, GSSAPI).
         */

        /*
         * Get the buffer as bytes.
         */
        IoBuffer buf = ( IoBuffer ) writeRequest.getMessage();
        int bufferLength = buf.remaining();
        byte[] bufferBytes = new byte[bufferLength];
        buf.get( bufferBytes );

        LOG.info( "Will use SASL to wrap message of length:  {}", bufferLength );

        /*
         * Ensure to not send larger SASL message than negotiated.
         */
        int max = maxBufferSize - 200;
        for ( int offset = 0; offset < bufferLength; offset += max )
        {
            int length = Math.min( bufferLength - offset, max );
            byte[] saslLayer = wrap( bufferBytes, offset, length );

            /*
             * Prepend 4 byte length.
             */
            IoBuffer saslLayerBuffer = IoBuffer.allocate( 4 + saslLayer.length );
            saslLayerBuffer.putInt( saslLayer.length );
            saslLayerBuffer.put( saslLayer );
            saslLayerBuffer.position( 0 );
            saslLayerBuffer.limit( 4 + saslLayer.length );

            LOG.debug( "Sending encrypted token of length {}.", saslLayerBuffer.limit() );
            nextFilter.filterWrite( session, new DefaultWriteRequest( saslLayerBuffer, writeRequest.getFuture() ) );
        }
    }


    private byte[] wrap( byte[] buffer, int offset, int length ) throws SaslException
    {
        if ( saslClient != null )
        {
            return saslClient.wrap( buffer, offset, length );
        }
        else
        {
            return saslServer.wrap( buffer, offset, length );
        }
    }


    private byte[] unwrap( byte[] buffer, int offset, int length ) throws SaslException
    {
        if ( saslClient != null )
        {
            return saslClient.unwrap( buffer, offset, length );
        }
        else
        {
            return saslServer.unwrap( buffer, offset, length );
        }
    }

}
