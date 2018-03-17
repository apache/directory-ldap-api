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


import org.apache.directory.api.ldap.codec.decorators.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionRequest;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponse;


/**
 * A Decorator for startTransaction request.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionRequestDecorator extends ExtendedRequestDecorator<StartTransactionRequest> implements
    StartTransactionRequest
{
    /** The internal startTransaction request */
    private StartTransactionRequest startTransactionRequest;


    /**
     * Creates a new instance of StartTransactionRequestDecorator.
     * 
     * @param codec The LDAP Service to use
     * @param decoratedMessage The canceled request
     */
    public StartTransactionRequestDecorator( LdapApiService codec, StartTransactionRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
        startTransactionRequest = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionResponse getResultResponse()
    {
        return ( StartTransactionResponse ) startTransactionRequest.getResultResponse();
    }
}
