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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulDisconnect.GracefulActionConstants;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequest;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownRequestImpl;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownResponse;
import org.apache.directory.api.ldap.extras.extended.gracefulShutdown.GracefulShutdownResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating cancel extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulShutdownFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of GracefulShutdownFactory.
     *
     * @param codec The codec for this factory.
     */
    public GracefulShutdownFactory( LdapApiService codec )
    {
        super( codec );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return GracefulShutdownRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public GracefulShutdownResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        GracefulShutdownResponseDecorator response = new GracefulShutdownResponseDecorator(
            codec, new GracefulShutdownResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public GracefulShutdownRequest newRequest( byte[] value )
    {
        GracefulShutdownRequestDecorator req = new GracefulShutdownRequestDecorator( codec,
            new GracefulShutdownRequestImpl() );
        req.setRequestValue( value );
        return req;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof GracefulShutdownRequestDecorator )
        {
            return modelRequest;
        }

        return new GracefulShutdownRequestDecorator( codec, ( GracefulShutdownRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof GracefulShutdownResponseDecorator )
        {
            return decoratedMessage;
        }

        return new GracefulShutdownResponseDecorator( codec, ( GracefulShutdownResponse ) decoratedMessage );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest )
    {
        int start  = buffer.getPos();
        GracefulShutdownRequest gracefulShutdownRequest = ( GracefulShutdownRequest ) extendedRequest;
        
        // The delay, if any
        if ( gracefulShutdownRequest.getDelay() != 0 )
        {
            BerValue.encodeInteger( buffer, 
                ( byte ) GracefulActionConstants.GRACEFUL_ACTION_DELAY_TAG, 
                gracefulShutdownRequest.getDelay() );
        }
        
        // The timeOffline
        if ( gracefulShutdownRequest.getTimeOffline() != 0 )
        {
            BerValue.encodeInteger( buffer, gracefulShutdownRequest.getTimeOffline() );
        }
        
        // The sequence
        BerValue.encodeSequence( buffer, start );
    }
}
