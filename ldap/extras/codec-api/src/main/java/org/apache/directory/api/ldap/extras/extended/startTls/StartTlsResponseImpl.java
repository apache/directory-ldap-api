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


import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * The RFC 4511 StartTLS response :
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTlsResponseImpl extends ExtendedResponseImpl implements StartTlsResponse
{
    /**
     * Create a new instance for the StartTls response
     * @param messageId The Message ID
     * @param rcode The result code
     * @param diagnosticMessage The diagnostic message
     */
    public StartTlsResponseImpl( int messageId, ResultCodeEnum rcode, String diagnosticMessage )
    {
        super( messageId, EXTENSION_OID );

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
        super.getLdapResult().setDiagnosticMessage( diagnosticMessage );
    }


    /**
     * Create a new instance for the StartTls response
     * @param messageId The Message ID
     * @param rcode The result code
     */
    public StartTlsResponseImpl( int messageId, ResultCodeEnum rcode )
    {
        super( messageId, EXTENSION_OID );

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
    }


    /**
     * Instantiates a new StartTls response.
     *
     * @param messageId the message id
     */
    public StartTlsResponseImpl( int messageId )
    {
        super( messageId, EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * Instantiates a new StartTls response.
     */
    public StartTlsResponseImpl()
    {
        super( EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "StartTlsResponse :" );
        sb.append( getLdapResult() );

        return sb.toString();
    }
}
