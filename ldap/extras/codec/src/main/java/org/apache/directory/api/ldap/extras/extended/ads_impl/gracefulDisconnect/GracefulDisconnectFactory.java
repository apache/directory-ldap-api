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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponse;
import org.apache.directory.api.ldap.extras.extended.gracefulDisconnect.GracefulDisconnectResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating cancel extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulDisconnectFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of GracefulDisconnectFactory.
     *
     * @param codec The codec for this factory.
     */
    public GracefulDisconnectFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequestDecorator<ExtendedRequest> decorate(
        ExtendedRequest modelRequest )
    {
        // Nothing to do (there's no request associated to GracefulDisconnectResponse)
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof GracefulDisconnectResponseDecorator )
        {
            return decoratedMessage;
        }

        return new GracefulDisconnectResponseDecorator( codec, ( GracefulDisconnectResponse ) decoratedMessage );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return GracefulDisconnectResponse.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest newRequest( byte[] value )
    {
        // Nothing to do (there's no request associated to GracefulDisconnectResponse)
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public GracefulDisconnectResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        GracefulDisconnectResponseDecorator req = new GracefulDisconnectResponseDecorator( codec,
            new GracefulDisconnectResponseImpl() );
        req.setResponseValue( encodedValue );
        
        return req;
    }
}
