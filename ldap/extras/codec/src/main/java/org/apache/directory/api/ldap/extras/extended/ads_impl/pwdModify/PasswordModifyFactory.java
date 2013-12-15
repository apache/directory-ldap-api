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
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.extended.PwdModifyRequest;
import org.apache.directory.api.ldap.extras.extended.PwdModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.PwdModifyResponse;
import org.apache.directory.api.ldap.extras.extended.PwdModifyResponseImpl;
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
public class PasswordModifyFactory implements ExtendedOperationFactory<PwdModifyRequest, PwdModifyResponse>
{
    private LdapApiService codec;


    public PasswordModifyFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    public String getOid()
    {
        return PwdModifyRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    public PwdModifyRequest newRequest()
    {
        return new PasswordModifyRequestDecorator( codec, new PwdModifyRequestImpl() );
    }


    /**
     * {@inheritDoc}
     */
    public PwdModifyResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        PasswordModifyResponseDecorator response = new PasswordModifyResponseDecorator( codec,
            new PwdModifyResponseImpl() );
        response.setResponseValue( encodedValue );
        return response;
    }


    /**
     * {@inheritDoc}
     */
    public PwdModifyRequest newRequest( byte[] value )
    {
        PasswordModifyRequestDecorator req = new PasswordModifyRequestDecorator( codec, new PwdModifyRequestImpl() );
        req.setRequestValue( value );
        return req;
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedRequestDecorator<PwdModifyRequest, PwdModifyResponse> decorate( ExtendedRequest<?> modelRequest )
    {
        if ( modelRequest instanceof PasswordModifyRequestDecorator )
        {
            return ( PasswordModifyRequestDecorator ) modelRequest;
        }

        return new PasswordModifyRequestDecorator( codec, ( PwdModifyRequest ) modelRequest );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponseDecorator<PwdModifyResponse> decorate( ExtendedResponse decoratedResponse )
    {
        if ( decoratedResponse instanceof PasswordModifyResponseDecorator )
        {
            return ( PasswordModifyResponseDecorator ) decoratedResponse;
        }

        if ( decoratedResponse instanceof PwdModifyResponse )
        {
            return new PasswordModifyResponseDecorator( codec, ( PwdModifyResponse ) decoratedResponse );
        }

        // It's an opaque extended operation
        ExtendedResponseDecorator<ExtendedResponse> response = ( ExtendedResponseDecorator<ExtendedResponse> ) decoratedResponse;

        // Decode the response, as it's an opaque operation
        Asn1Decoder decoder = new Asn1Decoder();

        byte[] value = response.getResponseValue();
        ByteBuffer buffer = ByteBuffer.wrap( value );

        PasswordModifyResponseContainer container = new PasswordModifyResponseContainer();
        PwdModifyResponse pwdModifyResponse = null;
        
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
            pwdModifyResponse = new PwdModifyResponseImpl(
                decoratedResponse.getMessageId(),
                ResultCodeEnum.OPERATIONS_ERROR,
                stackTrace );
        }

        PasswordModifyResponseDecorator decorated = new PasswordModifyResponseDecorator( codec, pwdModifyResponse );
        
        Control ppolicyControl = response.getControl( PasswordPolicy.OID );
        
        if( ppolicyControl != null )
        {
            decorated.addControl( ppolicyControl );
        }
        
        return decorated;
    }
}
