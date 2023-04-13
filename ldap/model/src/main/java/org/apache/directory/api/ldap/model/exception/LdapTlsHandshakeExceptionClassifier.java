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


import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.directory.api.ldap.model.exception.LdapTlsHandshakeFailCause.LdapApiReason;


public final class LdapTlsHandshakeExceptionClassifier
{
    private LdapTlsHandshakeExceptionClassifier()
    {
    }

    public static LdapTlsHandshakeFailCause classify( Throwable cause )
    {
        return classify( cause, null );
    }


    public static LdapTlsHandshakeFailCause classify( Throwable cause, X509Certificate certificate )
    {
        LdapTlsHandshakeFailCause failCause = new LdapTlsHandshakeFailCause();
        failCause.setCause( cause );

        Throwable rootCause = ExceptionUtils.getRootCause( cause );
        failCause.setRootCause( rootCause );

        if ( rootCause instanceof CertificateExpiredException )
        {
            failCause.setReason( BasicReason.EXPIRED );
            failCause.setReasonPhrase( "Certificate expired" );
        }
        else if ( rootCause instanceof CertificateNotYetValidException )
        {
            failCause.setReason( BasicReason.NOT_YET_VALID );
            failCause.setReasonPhrase( "Certificate not yet valid" );
        }
        else if ( rootCause instanceof CertPathBuilderException )
        {
            failCause.setReason( LdapApiReason.NO_VALID_CERTIFICATION_PATH );
            failCause.setReasonPhrase( "Failed to build certification path" );
            if ( certificate != null )
            {
                X500Principal issuerX500Principal = certificate.getIssuerX500Principal();
                X500Principal subjectX500Principal = certificate.getSubjectX500Principal();
                if ( issuerX500Principal.equals( subjectX500Principal ) )
                {
                    failCause.setReason( LdapApiReason.SELF_SIGNED );
                    failCause.setReasonPhrase( "Self signed certificate" );
                }
            }
        }
        else if ( rootCause instanceof CertPathValidatorException )
        {
            CertPathValidatorException cpve = ( CertPathValidatorException ) rootCause;
            failCause.setReason( cpve.getReason() );
            failCause.setReasonPhrase( "Failed to verify certification path" );
        }
        else
        {
            failCause.setReason( BasicReason.UNSPECIFIED );
            String failMessage = "Undefined";
            
            if ( cause != null )
            {
                failMessage += ", " + cause.getClass().getSimpleName();
            }
            
            failCause.setReasonPhrase( failMessage );
        }

        return failCause;
    }
}
