/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.extended.startTransaction;


import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;


/**
 * Implement the extended Start Transaction Request as described in RFC 5805.
 * 
 * It's grammar is :
 * 
 * <pre>
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *              requestName      [0] LDAPOID,
 *              requestValue     [1] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where 'requestName' is 1.3.6.1.1.21.1 and requestValue is absent.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionRequestImpl extends AbstractExtendedRequest implements StartTransactionRequest
{
    /**
     * Creates a new instance of StartTransactionRequestImpl.
     *
     * @param messageId the message id
     */
    public StartTransactionRequestImpl( int messageId )
    {
        super( messageId );
        setRequestName( EXTENSION_OID );
    }


    /**
     * Creates a new instance of StartTransactionRequestImpl.
     */
    public StartTransactionRequestImpl()
    {
        setRequestName( EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTransactionResponse getResultResponse()
    {
        if ( getResponse() == null )
        {
            setResponse( new StartTransactionResponseImpl() );
        }

        return ( StartTransactionResponse ) getResponse();
    }
}
