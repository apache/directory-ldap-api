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
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for EndTransaction request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionRequestDecorator extends ExtendedRequestDecorator<EndTransactionRequest> implements
    EndTransactionRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( EndTransactionRequestDecorator.class );

    /** The internal EndTransaction request */
    private EndTransactionRequest endTransactionRequest;


    /**
     * Creates a new instance of EndTransactionRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param decoratedMessage The canceled request
     */
    public EndTransactionRequestDecorator( LdapApiService codec, EndTransactionRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        endTransactionRequest = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponse getResultResponse()
    {
        return ( EndTransactionResponse ) endTransactionRequest.getResultResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getCommit()
    {
        return endTransactionRequest.getCommit();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCommit( boolean commit )
    {
        endTransactionRequest.setCommit( commit );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getTransactionId()
    {
        return endTransactionRequest.getTransactionId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTransactionId( byte[] transactionId )
    {
        endTransactionRequest.setTransactionId( transactionId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] requestValue )
    {
        EndTransactionRequestDecoder decoder = new EndTransactionRequestDecoder();

        try
        {
            if ( requestValue != null )
            {
                endTransactionRequest = decoder.decode( requestValue );

                this.requestValue = new byte[requestValue.length];
                System.arraycopy( requestValue, 0, this.requestValue, 0, requestValue.length );
            }
            else
            {
                this.requestValue = null;
            }
        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04165 ), e );
            throw new RuntimeException( e );
        }
    }
}
