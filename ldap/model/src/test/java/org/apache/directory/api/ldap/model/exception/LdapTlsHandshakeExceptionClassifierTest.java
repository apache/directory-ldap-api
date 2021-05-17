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


import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertPathValidatorException.Reason;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import org.apache.directory.api.ldap.model.exception.LdapTlsHandshakeFailCause.LdapApiReason;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


@Execution(ExecutionMode.CONCURRENT)
public class LdapTlsHandshakeExceptionClassifierTest
{
    @Test
    public void testClassifyNull()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier.classify( null );
        assertThat( classification.getReason(), equalTo( ( Reason ) BasicReason.UNSPECIFIED ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Unspecified" ) );
        assertThat( classification.getRootCause(), equalTo( null ) );
    }


    @Test
    public void testClassifyOther()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier
            .classify( new IOException( "foo" ) );
        assertThat( classification.getReason(), equalTo( ( Reason ) BasicReason.UNSPECIFIED ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Unspecified" ) );
        assertThat( classification.getRootCause(), instanceOf( IOException.class ) );
    }


    @Test
    public void testClassifyCertificateExpiredException()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier
            .classify( new CertificateExpiredException( "foo" ) );
        assertThat( classification.getReason(), equalTo( ( Reason ) BasicReason.EXPIRED ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Certificate expired" ) );
        assertThat( classification.getRootCause(), instanceOf( CertificateExpiredException.class ) );
    }


    @Test
    public void testClassifyCertificateNotYetValidException()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier
            .classify( new CertificateNotYetValidException( "foo" ) );
        assertThat( classification.getReason(), equalTo( ( Reason ) BasicReason.NOT_YET_VALID ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Certificate not yet valid" ) );
        assertThat( classification.getRootCause(), instanceOf( CertificateNotYetValidException.class ) );
    }


    @Test
    public void testClassifyCertPathBuilderException()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier
            .classify( new Exception( new CertPathBuilderException( "foo" ) ) );
        assertThat( classification.getReason(), equalTo( ( Reason ) LdapApiReason.NO_VALID_CERTIFICATION_PATH ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Failed to build certification path" ) );
        assertThat( classification.getRootCause(), instanceOf( CertPathBuilderException.class ) );
    }


    @Test
    public void testClassifyCertPathValidatorException()
    {
        LdapTlsHandshakeFailCause classification = LdapTlsHandshakeExceptionClassifier.classify(
            new Exception( new Exception( new Exception( new Exception(
                new CertPathValidatorException( "foo", null, null, -1, BasicReason.ALGORITHM_CONSTRAINED ) ) ) ) ) );
        assertThat( classification.getReason(), equalTo( ( Reason ) BasicReason.ALGORITHM_CONSTRAINED ) );
        assertThat( classification.getReasonPhrase(), equalTo( "Failed to verify certification path" ) );
        assertThat( classification.getRootCause(), instanceOf( CertPathValidatorException.class ) );
    }

}
