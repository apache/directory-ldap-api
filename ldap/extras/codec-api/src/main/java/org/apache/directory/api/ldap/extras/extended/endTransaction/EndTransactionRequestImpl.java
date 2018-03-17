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
package org.apache.directory.api.ldap.extras.extended.endTransaction;


import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;
import org.apache.directory.api.util.Strings;


/**
 * The EndTransactionRequest implementation. This is for the RFC 5805 End Transaction Request,
 * which grammar is :
 * <pre>
 * ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *              requestName      [0] LDAPOID,
 *              requestValue     [1] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where 'requestName' is 1.3.6.1.1.21.3 and requestValue is a BER encoded value. The 
 * syntax for this value is :
 * 
 * <pre>
 * txnEndReq ::= SEQUENCE {
 *         commit         BOOLEAN DEFAULT TRUE,
 *         identifier     OCTET STRING }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionRequestImpl extends AbstractExtendedRequest implements EndTransactionRequest
{
    /** The transaction ID received from the StartTransactionResponse */
    private byte[] transactionId;
    
    /** A flag telling of we should commit or rollback the transaction */
    private boolean commit = true;
    
    /**
     * Creates a new instance of EndTransactionRequestImpl.
     *
     * @param messageId the message id
     */
    public EndTransactionRequestImpl( int messageId )
    {
        super( messageId );
        setRequestName( EXTENSION_OID );
    }


    /**
     * Creates a new instance of EndTransactionRequestImpl.
     */
    public EndTransactionRequestImpl()
    {
        setRequestName( EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EndTransactionResponse getResultResponse()
    {
        if ( getResponse() == null )
        {
            setResponse( new EndTransactionResponseImpl() );
        }

        return ( EndTransactionResponse ) getResponse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getCommit()
    {
        return commit;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCommit( boolean commit )
    {
        this.commit = commit;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getTransactionId()
    {
        return Strings.copy( transactionId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTransactionId( byte[] transactionId )
    {
        this.transactionId = Strings.copy( transactionId );
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "EndTransactionRequest :" );
        sb.append( "\n    commit : " ).append( commit );

        sb.append( "\n    transactionId : " );

        if ( transactionId != null )
        {
            sb.append( Strings.dumpBytes( transactionId ) );
        }
        else
        {
            sb.append( "null" );
        }

        return sb.toString();
    }
}
