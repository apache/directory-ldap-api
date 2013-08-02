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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.PwdModifyRequest;
import org.apache.directory.api.ldap.extras.extended.PwdModifyRequestImpl;
import org.apache.directory.api.ldap.extras.extended.PwdModifyResponse;
import org.apache.directory.api.ldap.extras.extended.PwdModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


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
    public ExtendedResponseDecorator<PwdModifyResponse> decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof PasswordModifyResponseDecorator )
        {
            return ( PasswordModifyResponseDecorator ) decoratedMessage;
        }

        return new PasswordModifyResponseDecorator( codec, ( PwdModifyResponse ) decoratedMessage );
    }
}
