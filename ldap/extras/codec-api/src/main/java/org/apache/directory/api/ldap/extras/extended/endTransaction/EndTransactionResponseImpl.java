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


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * The End Transaction Extended Response implementation. It's described in RFC 5805 :
 * 
 * <pre>
 * ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *            COMPONENTS OF LDAPResult,
 *            responseName     [10] LDAPOID OPTIONAL,
 *            responseValue    [11] OCTET STRING OPTIONAL }
 * </pre>
 * 
 * where the responseName is not present, and the responseValue contains
 * a BER encoded value, defined by the following grammar :
 * 
 * <pre>
 * txnEndRes ::= SEQUENCE {
 *         messageID MessageID OPTIONAL,
 *              -- msgid associated with non-success resultCode
 *         updatesControls SEQUENCE OF updateControls SEQUENCE {
 *              messageID MessageID,
 *                   -- msgid associated with controls
 *              controls  Controls
 *         } OPTIONAL
 *    }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionResponseImpl extends ExtendedResponseImpl implements EndTransactionResponse
{
    /** The faulty Message ID, if any */
    private int failedMessageId = -1;
    
    /** The list of update controls for the message processed in the transaction */
    private List<UpdateControls> updateControls = new ArrayList<>();

    /**
     * Create a new EndTransactionResponseImpl object
     * 
     * @param failedMessageId The faulty messageId
     * @param rcode the result code
     */
    public EndTransactionResponseImpl( int failedMessageId, ResultCodeEnum resultCode )
    {
        super( failedMessageId );

        switch ( resultCode )
        {
            case SUCCESS:
                this.failedMessageId = -1;
                break;

            default:
                this.failedMessageId = failedMessageId;
        }

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( resultCode );
    }


    /**
     * Create a new EndTransactionResponseImpl instance
     * 
     * @param failedMessageId The request's messageId
     */
    public EndTransactionResponseImpl( int failedMessageId )
    {
        super( failedMessageId );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * Create a new StartTransactionResponseImpl instance
     */
    public EndTransactionResponseImpl()
    {
        super( EndTransactionRequest.EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.UNWILLING_TO_PERFORM );
    }


    /**
     * Gets the OID uniquely identifying this extended response (a.k.a. its
     * name). It's a null value for the Cancel response
     * 
     * @return the OID of the extended response type.
     */
    @Override
    public String getResponseName()
    {
        return "";
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public int getFailedMessageId()
    {
        return failedMessageId;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setFailedMessageId( int failedMessageId )
    {
        this.failedMessageId = failedMessageId;
    }
    
    /**
     * @return the updateControls
     */
    @Override
    public List<UpdateControls> getUpdateControls()
    {
        return updateControls;
    }


    /**
     * @param updateControls the updateControls to set
     */
    public void setUpdateControls( List<UpdateControls> updateControls )
    {
        this.updateControls = updateControls;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;

        hash = hash * 17 + failedMessageId;
        
        for ( UpdateControls updateControl : updateControls )
        {
            hash = hash * 17 + updateControl.hashCode();
        }

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

        if ( !( obj instanceof EndTransactionResponse ) )
        {
            return false;
        }
        
        EndTransactionResponse that = ( EndTransactionResponse ) obj;
        
        if ( failedMessageId != that.getFailedMessageId() )
        {
            return false;
        }
        
        for ( UpdateControls updateControl : updateControls )
        {
            if ( !that.getUpdateControls().contains( updateControl ) )
            {
                return false;
            }
        }
        
        return true;
    }
}
