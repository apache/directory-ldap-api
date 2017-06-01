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
package org.apache.directory.api.ldap.extras.extended.ads_impl.startTls;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsResponse;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating SartTls extended reques/response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTlsFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of StartTlsFactory.
     *
     * @param codec The codec for this factory.
     */
    public StartTlsFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return StartTlsRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        StartTlsResponseDecorator response = new StartTlsResponseDecorator( codec,
            new StartTlsResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsRequest newRequest( byte[] value )
    {
        StartTlsRequestDecorator req = new StartTlsRequestDecorator( codec, new StartTlsRequestImpl() );

        if ( value != null )
        {
            req.setRequestValue( value );
        }

        return req;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof StartTlsRequestDecorator )
        {
            return ( StartTlsRequestDecorator ) modelRequest;
        }

        return new StartTlsRequestDecorator( codec, ( StartTlsRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsResponseDecorator decorate( ExtendedResponse decoratedResponse )
    {
        if ( decoratedResponse instanceof StartTlsResponseDecorator )
        {
            return ( StartTlsResponseDecorator ) decoratedResponse;
        }

        if ( decoratedResponse instanceof StartTlsResponse )
        {
            return new StartTlsResponseDecorator( codec, ( StartTlsResponse ) decoratedResponse );
        }

        // It's an opaque extended operation
        @SuppressWarnings("unchecked")
        ExtendedResponseDecorator<ExtendedResponse> response = ( ExtendedResponseDecorator<ExtendedResponse> ) decoratedResponse;

        // Decode the response, as it's an opaque operation
        StartTlsResponse startTlsResponse = new StartTlsResponseImpl( response.getMessageId() );
        
        startTlsResponse.getLdapResult().setResultCode( response.getLdapResult().getResultCode() );
        startTlsResponse.getLdapResult().setDiagnosticMessage( response.getLdapResult().getDiagnosticMessage() );
        return new StartTlsResponseDecorator( codec, new StartTlsResponseImpl() );
    }
}
