/*
 * Licensed to the Apache Software Foundation (ASF) under one
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
package org.apache.directory.ldap.client.api.future;


import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.ldap.client.api.LdapConnection;


/**
 * A Future to manage ExtendedRequests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ExtendedFuture extends MultipleResponseFuture<Response>
{
    /** 
     * The extendedRequest : we need it to find which request is associated 
     * with a response, when this response has no name */
    ExtendedRequest extendedRequest;
    
    /**
     * Creates a new instance of ExtendedFuture.
     *
     * @param connection the LDAP connection
     * @param messageId The associated messageId
     */
    public ExtendedFuture( LdapConnection connection, int messageId )
    {
        super( connection, messageId );
    }


    /**
     * Get the extended request instance
     * 
     * @return the extendedRequest
     */
    public ExtendedRequest getExtendedRequest()
    {
        return extendedRequest;
    }


    /**
     * Set the ExtendedRequest
     * 
     * @param extendedRequest the extendedRequest to set
     */
    public void setExtendedRequest( ExtendedRequest extendedRequest )
    {
        this.extendedRequest = extendedRequest;
    }


    /**
     * Set the associated Response in this Future
     * 
     * @param response The response to add into the Future
     * @throws InterruptedException if the operation has been cancelled by client
     */
    public void set( ExtendedResponse response ) throws InterruptedException
    {
        if ( response.getResponseName() == null )
        {
            // Feed the response with the request's OID 
            response.setResponseName( extendedRequest.getRequestName() );
        }
        
        queue.add( response );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "ExtendedFuture" ).append( super.toString() );

        return sb.toString();
    }
}
