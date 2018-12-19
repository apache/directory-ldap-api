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
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequest;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequestImpl;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;


/**
 * An {@link ExtendedOperationFactory} for creating WhoAmI extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of WhoAmIFactory.
     *
     * @param codec The codec for this factory.
     */
    public WhoAmIFactory( LdapApiService codec )
    {
        super( codec );
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
        return WhoAmIResponseDecoder.decode( new WhoAmIResponseImpl(), encodedValue );
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
        byte[] value = response.getResponseValue();
        
        if ( value == null )
        {
            value = Strings.EMPTY_BYTES;
        }
        
        ByteBuffer buffer = ByteBuffer.wrap( value );

        WhoAmIResponse whoAmIResponse = new WhoAmIResponseImpl( response.getMessageId() );

        try
        {
            WhoAmIResponseDecoder.decode( whoAmIResponse, buffer.array() );

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
    

    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedResponse extendedResponse )
    {
        if ( extendedResponse == null )
        {
            return;
        }

        // Reset the responseName, it should always be null for a WhoAMI extended operation
        extendedResponse.setResponseName( null );
        
        // The authzID as a opaque byte array
        byte[] authzid =  ( ( WhoAmIResponse ) extendedResponse ).getAuthzId();
        
        if ( !Strings.isEmpty( authzid ) )
        {
            buffer.put( authzid );
        }
    }
}
