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
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequest;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequestImpl;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * An {@link ExtendedOperationFactory} for creating WhoAmI extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of WhoAmIFactory.
     *
     * @param codec The codec for this factory.
     */
    public WhoAmIFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return WhoAmIRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        WhoAmIResponseDecorator response = new WhoAmIResponseDecorator( codec,
            new WhoAmIResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIRequest newRequest( byte[] value )
    {
        WhoAmIRequestDecorator req = new WhoAmIRequestDecorator( codec, new WhoAmIRequestImpl() );

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
    public WhoAmIRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof WhoAmIRequestDecorator )
        {
            return ( WhoAmIRequestDecorator ) modelRequest;
        }

        return new WhoAmIRequestDecorator( codec, ( WhoAmIRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIResponseDecorator decorate( ExtendedResponse decoratedResponse )
    {
        if ( decoratedResponse instanceof WhoAmIResponseDecorator )
        {
            return ( WhoAmIResponseDecorator ) decoratedResponse;
        }

        if ( decoratedResponse instanceof WhoAmIResponse )
        {
            return new WhoAmIResponseDecorator( codec, ( WhoAmIResponse ) decoratedResponse );
        }

        // It's an opaque extended operation
        @SuppressWarnings("unchecked")
        ExtendedResponseDecorator<ExtendedResponse> response = ( ExtendedResponseDecorator<ExtendedResponse> ) decoratedResponse;

        // Decode the response, as it's an opaque operation
        Asn1Decoder decoder = new Asn1Decoder();

        byte[] value = response.getResponseValue();
        ByteBuffer buffer = ByteBuffer.wrap( value );

        WhoAmIResponseContainer container = new WhoAmIResponseContainer();
        WhoAmIResponse whoAmIResponse = null;

        try
        {
            decoder.decode( buffer, container );

            whoAmIResponse = container.getWhoAmIResponse();

            // Now, update the created response with what we got from the extendedResponse
            whoAmIResponse.getLdapResult().setResultCode( response.getLdapResult().getResultCode() );
            whoAmIResponse.getLdapResult().setDiagnosticMessage( response.getLdapResult().getDiagnosticMessage() );
            whoAmIResponse.getLdapResult().setMatchedDn( response.getLdapResult().getMatchedDn() );
            whoAmIResponse.getLdapResult().setReferral( response.getLdapResult().getReferral() );
        }
        catch ( DecoderException de )
        {
            StringWriter sw = new StringWriter();
            de.printStackTrace( new PrintWriter( sw ) );
            String stackTrace = sw.toString();

            // Error while decoding the value. 
            whoAmIResponse = new WhoAmIResponseImpl(
                decoratedResponse.getMessageId(),
                ResultCodeEnum.OPERATIONS_ERROR,
                stackTrace );
        }

        return new WhoAmIResponseDecorator( codec, whoAmIResponse );
    }
}
