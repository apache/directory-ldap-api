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


import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.startTransaction.StartTransactionResponse;
import org.apache.directory.api.util.Strings;


/**
 * A Decorator for EndTransactionResponses.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionResponseDecorator extends ExtendedResponseDecorator<StartTransactionResponse> implements StartTransactionResponse
{
    /** The startTransaction response */
    private StartTransactionResponse startTransactionResponse;

    /**
     * Creates a new instance of EndTransactionResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public StartTransactionResponseDecorator( LdapApiService codec, StartTransactionResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        startTransactionResponse = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        this.responseValue = Strings.copy( responseValue );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getTransactionId()
    {
        return startTransactionResponse.getTransactionId();
    }
}
