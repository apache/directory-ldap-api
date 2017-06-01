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
package org.apache.directory.api.ldap.extras.extended.cancel;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * 
 * The response sent back from the server after the Cancel extended operation is performed.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CancelResponseImpl extends ExtendedResponseImpl implements CancelResponse
{
    /**
     * Create a new CancelResponse instance
     * 
     * @param messageId The request's messageId
     * @param rcode the result code
     */
    public CancelResponseImpl( int messageId, ResultCodeEnum rcode )
    {
        super( messageId );

        switch ( rcode )
        {
            case SUCCESS:
            case CANCELED:
            case CANNOT_CANCEL:
            case NO_SUCH_OPERATION:
            case TOO_LATE:
                break;

            default:
                throw new IllegalArgumentException( I18n.err( I18n.ERR_04166, ResultCodeEnum.SUCCESS,
                    ResultCodeEnum.OPERATIONS_ERROR, ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS ) );
        }

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
    }


    /**
     * Create a new CancelResponse instance
     * 
     * @param messageId The request's messageId
     */
    public CancelResponseImpl( int messageId )
    {
        super( messageId );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * Create a new CancelResponse instance
     */
    public CancelResponseImpl()
    {
        super( CancelRequest.EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
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
    public int hashCode()
    {
        int hash = 37;
        // Seems simple but look at the equals() method ...
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

        return obj instanceof CancelResponseImpl;
    }
}
