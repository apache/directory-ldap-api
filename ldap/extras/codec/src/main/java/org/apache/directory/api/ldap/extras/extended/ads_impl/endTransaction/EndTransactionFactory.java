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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequestImpl;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponseImpl;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * An {@link ExtendedOperationFactory} for creating EndTransaction extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionFactory implements ExtendedOperationFactory
{
    private LdapApiService codec;


    /**
     * Creates a new instance of EndTransactionFactory.
     *
     * @param codec The codec for this factory.
     */
    public EndTransactionFactory( LdapApiService codec )
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
    public EndTransactionResponse newResponse( byte[] encodedValue ) throws DecoderException
    {
        EndTransactionResponseDecorator response = new EndTransactionResponseDecorator( codec, new EndTransactionResponseImpl() );
        response.setResponseValue( encodedValue );

        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionRequest newRequest( byte[] value )
    {
        return new EndTransactionRequestDecorator( codec, new EndTransactionRequestImpl() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionRequestDecorator decorate( ExtendedRequest modelRequest )
    {
        if ( modelRequest instanceof EndTransactionRequestDecorator )
        {
            return ( EndTransactionRequestDecorator ) modelRequest;
        }

        return new EndTransactionRequestDecorator( codec, null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponseDecorator decorate( ExtendedResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof EndTransactionResponseDecorator )
        {
            return ( EndTransactionResponseDecorator ) decoratedMessage;
        }

        return new EndTransactionResponseDecorator( codec, null );
    }
}
