/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
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


import java.util.Arrays;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.AbstractExtendedResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;


/**
 * The interface for Start Transaction Extended Response. It's described in RFC 5805 :
 * 
 * <pre>
 * StartTransactionResponse ::= [APPLICATION 24] SEQUENCE {
 *            COMPONENTS OF LDAPResult,
 *            responseValue    [11] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where the responseName is not present, and the responseValue contain
 * a transaction identifier when the result is SUCCESS.
 * 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTransactionResponseImpl extends AbstractExtendedResponse implements StartTransactionResponse
{
    /** The transaction ID if the request was successful */
    private byte[] transactionId;
    
    /**
     * Create a new StartTransactionResponseImpl object
     * 
     * @param messageId The messageId
     * @param resultCode the result code
     * @param transactionId The transaction ID 
     */
    public StartTransactionResponseImpl( int messageId, ResultCodeEnum resultCode, byte[] transactionId )
    {
        super( messageId );

        switch ( resultCode )
        {
            case SUCCESS:
                this.transactionId = Strings.copy( transactionId );
                break;
                
            case CANCELED:
            case CANNOT_CANCEL:
            case NO_SUCH_OPERATION:
            case TOO_LATE:
                break;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_13503_RESULT_CODE_SHOULD_BE_IN, ResultCodeEnum.SUCCESS,
                    ResultCodeEnum.OPERATIONS_ERROR, ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS ) );
        }

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( resultCode );
    }


    /**
     * Create a new StartTransactionResponseImpl instance
     * 
     * @param messageId The request's messageId
     * @param transactionId The transaction ID 
     */
    public StartTransactionResponseImpl( int messageId, byte[] transactionId )
    {
        super( messageId );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
        this.transactionId = Strings.copy( transactionId );
    }


    /**
     * Create a new StartTransactionResponseImpl instance
     * 
     * @param transactionId The transaction ID 
     */
    public StartTransactionResponseImpl( byte[] transactionId )
    {
        super( StartTransactionRequest.EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
        this.transactionId = Strings.copy( transactionId );
    }


    /**
     * Create a new StartTransactionResponseImpl instance
     */
    public StartTransactionResponseImpl()
    {
        super( StartTransactionRequest.EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.UNWILLING_TO_PERFORM );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        
        if ( transactionId != null )
        {
            for ( byte b : transactionId )
            {
                hash += hash * 17 + b;
            }
        }
        
        hash = hash * 17 + getClass().getName().hashCode();

        return hash;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !( obj instanceof StartTransactionResponseImpl ) )
        {
            return false;
        }
        
        return Arrays.equals( transactionId, ( ( StartTransactionResponseImpl ) obj ).transactionId );
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
     * Set the transaction ID
     * 
     * @param transactionId The transaction ID to set
     */
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

        sb.append( "StartTransactionResponse :" );
        sb.append( "\n    transactionID : " );

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
