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
package org.apache.directory.api.ldap.model.exception;


/**
 * A LdapTlsException is thrown if the SSL/TLS handshake failed.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapTlsHandshakeException extends LdapException
{
    private static final long serialVersionUID = 1L;

    private LdapTlsHandshakeFailCause failCause;


    /**
     * The constructor with a reason string argument.
     * 
     * @param message the message
     * @param cause the root cause
     */
    public LdapTlsHandshakeException( String message, Throwable cause )
    {
        super( message, cause );
        this.failCause = LdapTlsHandshakeExceptionClassifier.classify( cause, null );
    }


    public LdapTlsHandshakeFailCause getFailCause()
    {
        return failCause;
    }


    @Override
    public String getMessage()
    {
        String message = super.getMessage();

        message += ", reason: " + failCause.getReasonPhrase();
        Throwable rootCause = failCause.getRootCause();
        if ( rootCause != null && rootCause != this )
        {
            message += ": " + rootCause.getMessage();
        }

        return message;
    }

}
