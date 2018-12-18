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
package org.apache.directory.api.ldap.model.exception;


import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import org.apache.commons.lang3.exception.ExceptionUtils;


/**
 * A LdapTlsException is thrown if the SSL/TLS handshake failed.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapTlsHandshakeException extends LdapException
{
    private static final long serialVersionUID = 1L;

    private Throwable rootCause;
    private String reasonPhrase;


    /**
     * The constructor with a reason string argument.
     * 
     * @param message the message
     * @param cause the root cause
     */
    public LdapTlsHandshakeException( String message, Throwable cause )
    {
        super( message, cause );
        classify();
    }


    private void classify()
    {
        rootCause = ExceptionUtils.getRootCause( getCause() );

        if ( rootCause instanceof CertificateExpiredException )
        {
            this.reasonPhrase = "Certificate expired";
        }
        else if ( rootCause instanceof CertificateNotYetValidException )
        {
            this.reasonPhrase = "Certificate not yet valid";
        }
        else if ( rootCause instanceof CertPathBuilderException )
        {
            this.reasonPhrase = "Failed to build certification path";
        }
        else if ( rootCause instanceof CertPathValidatorException )
        {
            CertPathValidatorException cpve = ( CertPathValidatorException ) rootCause;
            cpve.getReason();
            this.reasonPhrase = "Failed to verify certification path";
        }
        else
        {
            this.reasonPhrase = "Unspecified";
        }
    }


    @Override
    public String getMessage()
    {
        String message = super.getMessage();

        message += ", reason: " + reasonPhrase;
        if ( rootCause != null && rootCause != this )
        {
            message += ": " + rootCause.getMessage();
        }

        return message;
    }


    public String getReasonPhrase()
    {
        return reasonPhrase;
    }


    public Throwable getRootCause()
    {
        return rootCause;
    }
}
