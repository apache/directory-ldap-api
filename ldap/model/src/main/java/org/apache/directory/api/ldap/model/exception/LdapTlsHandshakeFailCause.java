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


import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertPathValidatorException.Reason;


public class LdapTlsHandshakeFailCause
{
    private Throwable cause;
    private Throwable rootCause;
    private Reason reason;
    private String reasonPhrase;


    public LdapTlsHandshakeFailCause()
    {
    }


    public LdapTlsHandshakeFailCause( Throwable cause, Throwable rootCause, Reason reason, String reasonPhrase )
    {
        this.cause = cause;
        this.rootCause = rootCause;
        this.reason = reason;
        this.reasonPhrase = reasonPhrase;
    }


    public Throwable getCause()
    {
        return cause;
    }


    public void setCause( Throwable cause )
    {
        this.cause = cause;
    }


    public Throwable getRootCause()
    {
        return rootCause;
    }


    public void setRootCause( Throwable rootCause )
    {
        this.rootCause = rootCause;
    }


    public Reason getReason()
    {
        return reason;
    }


    public void setReason( Reason reason )
    {
        this.reason = reason;
    }


    public String getReasonPhrase()
    {
        return reasonPhrase;
    }


    public void setReasonPhrase( String reasonPhrase )
    {
        this.reasonPhrase = reasonPhrase;
    }

    /**
     * Additional reasons.
     * 
     * @see BasicReason
     *
     */
    public enum LdapApiReason implements Reason
    {
        NO_VALID_CERTIFICATION_PATH,
        SELF_SIGNED,
        HOST_NAME_VERIFICATION_FAILED,
    }


    public String getMessage()
    {
        String message = reasonPhrase;
        if ( rootCause != null && rootCause != cause )
        {
            message += ": " + rootCause.getMessage();
        }
        return message;
    }

}
