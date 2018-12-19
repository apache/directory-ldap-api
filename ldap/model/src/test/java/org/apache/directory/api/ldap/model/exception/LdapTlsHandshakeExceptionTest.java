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


import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

import org.junit.Test;


public class LdapTlsHandshakeExceptionTest
{
    @Test
    public void testClassifyNull()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg", null );
        assertThat( e.getMessage(), equalTo( "msg, reason: Unspecified" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Unspecified" ) );
        assertThat( e.getRootCause(), equalTo( null ) );
    }


    @Test
    public void testClassifyOther()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg", new IOException( "foo" ) );
        assertThat( e.getMessage(), equalTo( "msg, reason: Unspecified: foo" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Unspecified" ) );
        assertThat( e.getRootCause(), instanceOf( IOException.class ) );
    }


    @Test
    public void testClassifyCertificateExpiredException()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg", new CertificateExpiredException( "foo" ) );
        assertThat( e.getMessage(), equalTo( "msg, reason: Certificate expired: foo" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Certificate expired" ) );
        assertThat( e.getRootCause(), instanceOf( CertificateExpiredException.class ) );
    }


    @Test
    public void testClassifyCertificateNotYetValidException()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg",
            new CertificateNotYetValidException( "foo" ) );
        assertThat( e.getMessage(), equalTo( "msg, reason: Certificate not yet valid: foo" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Certificate not yet valid" ) );
        assertThat( e.getRootCause(), instanceOf( CertificateNotYetValidException.class ) );
    }


    @Test
    public void testClassifyCertPathBuilderException()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg",
            new Exception( new CertPathBuilderException( "foo" ) ) );
        assertThat( e.getMessage(), equalTo( "msg, reason: Failed to build certification path: foo" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Failed to build certification path" ) );
        assertThat( e.getRootCause(), instanceOf( CertPathBuilderException.class ) );
    }


    @Test
    public void testClassifyCertPathValidatorException()
    {
        LdapTlsHandshakeException e = new LdapTlsHandshakeException( "msg",
            new Exception( new Exception( new Exception( new Exception(
                new CertPathValidatorException( "foo", null, null, -1, BasicReason.ALGORITHM_CONSTRAINED ) ) ) ) ) );
        assertThat( e.getMessage(), equalTo( "msg, reason: Failed to verify certification path: foo" ) );
        assertThat( e.getReasonPhrase(), equalTo( "Failed to verify certification path" ) );
        assertThat( e.getRootCause(), instanceOf( CertPathValidatorException.class ) );
    }
}
