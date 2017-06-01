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
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequest;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponse;
import org.apache.directory.api.ldap.extras.extended.pwdModify.PasswordModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * An {@link ExtendedOperationFactory} for creating PwdModify extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordModifyFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of PasswordModifyFactory.
     *
     * @param codec The codec for this factory.
     */
    public PasswordModifyFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return PasswordModifyRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        PasswordModifyResponseDecorator response = new PasswordModifyResponseDecorator( codec,
            new PasswordModifyResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordModifyRequest newRequest( byte[] value )
    {
        PasswordModifyRequestDecorator req = new PasswordModifyRequestDecorator( codec, new PasswordModifyRequestImpl() );

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
    public PasswordModifyRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof PasswordModifyRequestDecorator )
        {
            return ( PasswordModifyRequestDecorator ) modelRequest;
        }

        return new PasswordModifyRequestDecorator( codec, ( PasswordModifyRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
public PasswordModifyResponseDecorator decorate( ExtendedResponse decoratedResponse )
    {
        if ( decoratedResponse instanceof PasswordModifyResponseDecorator )
        {
            return ( PasswordModifyResponseDecorator ) decoratedResponse;
        }

        if ( decoratedResponse instanceof PasswordModifyResponse )
        {
            return new PasswordModifyResponseDecorator( codec, ( PasswordModifyResponse ) decoratedResponse );
        }

        // It's an opaque extended operation
        @SuppressWarnings("unchecked")
        ExtendedResponseDecorator<ExtendedResponse> response = ( ExtendedResponseDecorator<ExtendedResponse> ) decoratedResponse;

        // Decode the response, as it's an opaque operation
        Asn1Decoder decoder = new Asn1Decoder();

        byte[] value = response.getResponseValue();
        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();
        
        PasswordModifyResponse pwdModifyResponse;
        
        if ( value != null )
        {
            ByteBuffer buffer = ByteBuffer.wrap( value );
    
            try
            {
                decoder.decode( buffer, container );
                pwdModifyResponse = container.getPwdModifyResponse();

                // Now, update the created response with what we got from the extendedResponse
                pwdModifyResponse.getLdapResult().setResultCode( response.getLdapResult().getResultCode() );
                pwdModifyResponse.getLdapResult().setDiagnosticMessage( response.getLdapResult().getDiagnosticMessage() );
                pwdModifyResponse.getLdapResult().setMatchedDn( response.getLdapResult().getMatchedDn() );
                pwdModifyResponse.getLdapResult().setReferral( response.getLdapResult().getReferral() );
            }
            catch ( DecoderException de )
            {
                StringWriter sw = new StringWriter();
                de.printStackTrace( new PrintWriter( sw ) );
                String stackTrace = sw.toString();
    
                // Error while decoding the value. 
                pwdModifyResponse = new PasswordModifyResponseImpl(
                    decoratedResponse.getMessageId(),
                    ResultCodeEnum.OPERATIONS_ERROR,
                    stackTrace );
            }
        }
        else
        {
            pwdModifyResponse = new PasswordModifyResponseImpl();
    
            // Now, update the created response with what we got from the extendedResponse
            pwdModifyResponse.getLdapResult().setResultCode( response.getLdapResult().getResultCode() );
            pwdModifyResponse.getLdapResult().setDiagnosticMessage( response.getLdapResult().getDiagnosticMessage() );
            pwdModifyResponse.getLdapResult().setMatchedDn( response.getLdapResult().getMatchedDn() );
            pwdModifyResponse.getLdapResult().setReferral( response.getLdapResult().getReferral() );
        }

        PasswordModifyResponseDecorator decorated = new PasswordModifyResponseDecorator( codec, pwdModifyResponse );

        Control ppolicyControl = response.getControl( PasswordPolicy.OID );

        if ( ppolicyControl != null )
        {
            decorated.addControl( ppolicyControl );
        }

        return decorated;
    }
}
