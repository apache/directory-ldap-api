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
package org.apache.directory.api.ldap.extras.extended.startTls;


import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;


/**
 * The RFC 4511 StartTLS request
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTlsRequestImpl extends AbstractExtendedRequest implements StartTlsRequest
{
    /**
     * Create a new instance of the StartTlsRequest extended operation
     */
    public StartTlsRequestImpl()
    {
        setRequestName( EXTENSION_OID );
    }


    /**
     * Create a new instance of the StartTlsRequest extended operation
     * 
     * @param messageId The message ID
     */
    public StartTlsRequestImpl( int messageId )
    {
        super( messageId );
        setRequestName( EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsResponse getResultResponse()
    {
        if ( getResponse() == null )
        {
            setResponse( new StartTlsResponseImpl( getMessageId() ) );
        }

        return ( StartTlsResponse ) getResponse();
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return "StartTLS extended request";
    }
}
