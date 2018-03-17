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
package org.apache.directory.api.ldap.extras.extended.ads_impl.startTransaction;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionRequestImpl;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating StartTransaction extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of StartTransactionFactory.
     *
     * @param codec The codec for this factory.
     */
    public StartTransactionFactory( LdapApiService codec )
    {
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return CancelRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        StartTransactionResponseDecorator response = 
            new StartTransactionResponseDecorator( codec, new StartTransactionResponseImpl() );
        response.setResponseValue( encodedValue );

        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionRequest newRequest( byte[] value )
    {
        return new StartTransactionRequestDecorator( codec, new StartTransactionRequestImpl() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof StartTransactionRequestDecorator )
        {
            return ( StartTransactionRequestDecorator ) modelRequest;
        }

        return new StartTransactionRequestDecorator( codec, null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionResponseDecorator decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof StartTransactionResponseDecorator )
        {
            return ( StartTransactionResponseDecorator ) decoratedMessage;
        }

        return new StartTransactionResponseDecorator( codec, null );
    }
}
