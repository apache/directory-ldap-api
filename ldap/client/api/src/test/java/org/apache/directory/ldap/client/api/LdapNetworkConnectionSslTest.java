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
package org.apache.directory.ldap.client.api;


import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


/**
 * Tests that LdapNetworkConnection enforces TLS hostname verification as required
 * by RFC 2830 Section 3.6 / RFC 4513 (CWE-297 mitigation).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapNetworkConnectionSslTest
{
    /**
     * Self-signed certificate whose CN (wrong.host.invalid) intentionally does not
     * match the loopback hostname used by the test client ("localhost").
     * Generated once per test class run using BouncyCastle, entirely in memory.
     */
    private static SSLContext serverSslContext;
    private static X509Certificate serverCert;


    /**
     * Generates an RSA key pair and a self-signed X.509 certificate in memory using
     * BouncyCastle. No temporary files or external processes are required.
     */
    @BeforeAll
    static void generateMismatchedCertificate() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance( "RSA" );
        kpg.initialize( 2048, new SecureRandom() );
        KeyPair keyPair = kpg.generateKeyPair();

        Instant now = Instant.now();
        X500Name subject = new X500Name( "CN=wrong.host.invalid,O=Test,C=US" );

        ContentSigner signer = new JcaContentSignerBuilder( "SHA256WithRSA" )
            .build( keyPair.getPrivate() );

        serverCert = new JcaX509CertificateConverter()
            .getCertificate(
                new JcaX509v3CertificateBuilder(
                    subject,
                    BigInteger.valueOf( now.toEpochMilli() ),
                    Date.from( now ),
                    Date.from( now.plus( 1, ChronoUnit.DAYS ) ),
                    subject,
                    keyPair.getPublic() )
                .build( signer ) );

        KeyStore serverKs = KeyStore.getInstance( "PKCS12" );
        serverKs.load( null, null );
        serverKs.setKeyEntry( "server", keyPair.getPrivate(), new char[0],
            new java.security.cert.Certificate[]{ serverCert } );

        KeyManagerFactory kmf = KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm() );
        kmf.init( serverKs, new char[0] );

        serverSslContext = SSLContext.getInstance( "TLS" );
        serverSslContext.init( kmf.getKeyManagers(), null, null );
    }


    /**
     * Builds a {@link TrustManagerFactory} that trusts only {@link #serverCert}, so the
     * PKIX TrustManager accepts the certificate chain but still enforces hostname
     * verification via SSLParameters.endpointIdentificationAlgorithm.
     */
    private static TrustManagerFactory buildPkixTrustManager() throws Exception
    {
        KeyStore trustStore = KeyStore.getInstance( "PKCS12" );
        trustStore.load( null, null );
        trustStore.setCertificateEntry( "trusted-server", serverCert );
        TrustManagerFactory tmf = TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
        tmf.init( trustStore );
        return tmf;
    }


    /**
     * Starts a local TLS daemon thread. When {@code expectClientAbort} is true the server
     * silently swallows the handshake exception (the client tears the connection down).
     * When false the server completes the handshake and waits for the client to close.
     */
    private static Thread startTlsServer( SSLServerSocket serverSocket, boolean expectClientAbort )
    {
        Thread t = new Thread( () ->
        {
            try
            {
                SSLSocket client = ( SSLSocket ) serverSocket.accept();
                client.setSoTimeout( 5_000 );
                try
                {
                    client.startHandshake();
                    if ( !expectClientAbort )
                    {
                        client.getInputStream().read();
                    }
                }
                catch ( Exception ignored )
                {
                }
                client.close();
            }
            catch ( Exception ignored )
            {
            }
        } );
        t.setDaemon( true );
        t.start();
        return t;
    }


    /**
     * Behavioural test: the server presents a BouncyCastle-generated certificate for
     * CN=wrong.host.invalid but the client connects to "localhost". The standard PKIX
     * TrustManager accepts the certificate chain, then checks the hostname via
     * SSLParameters.endpointIdentificationAlgorithm (set to "LDAPS" by the fix). It
     * finds the mismatch and aborts the handshake, so connect() must throw LdapException.
     * Without the fix the algorithm would be null and the check silently skipped.
     */
    @Test
    public void testSslHandshakeRejectedWhenCertHostnameMismatches() throws Exception
    {
        TrustManagerFactory tmf = buildPkixTrustManager();

        SSLServerSocketFactory ssf = serverSslContext.getServerSocketFactory();
        try ( SSLServerSocket serverSocket = ( SSLServerSocket ) ssf.createServerSocket( 0 ) )
        {
            serverSocket.setSoTimeout( 10_000 );
            int port = serverSocket.getLocalPort();
            Thread serverThread = startTlsServer( serverSocket, true );

            LdapNetworkConnection conn = new LdapNetworkConnection( "localhost", port,
                tmf.getTrustManagers() );
            conn.setTimeOut( 5_000L );
            try
            {
                assertThrows( LdapException.class, () -> conn.connect(),
                    "connect() must throw when the server certificate CN does not match 'localhost'" );
            }
            finally
            {
                conn.close();
                serverThread.join( 5_000L );
            }
        }
    }


    /**
     * Verifies that {@link NoVerificationTrustManager} intentionally bypasses hostname
     * verification. Because it extends {@link javax.net.ssl.X509ExtendedTrustManager},
     * JSSE delegates ALL certificate validation — including the hostname check that would
     * normally be triggered by SSLParameters.endpointIdentificationAlgorithm — to its
     * (no-op) checkServerTrusted method. The handshake therefore succeeds even though the
     * server CN does not match "localhost".
     */
    @Test
    public void testSslHandshakeSucceedsWithNoVerificationTrustManagerEvenOnCertHostnameMismatch() throws Exception
    {
        SSLServerSocketFactory ssf = serverSslContext.getServerSocketFactory();
        try ( SSLServerSocket serverSocket = ( SSLServerSocket ) ssf.createServerSocket( 0 ) )
        {
            serverSocket.setSoTimeout( 10_000 );
            int port = serverSocket.getLocalPort();
            Thread serverThread = startTlsServer( serverSocket, false );

            LdapNetworkConnection conn = new LdapNetworkConnection( "localhost", port,
                new NoVerificationTrustManager() );
            conn.setTimeOut( 5_000L );
            try
            {
                conn.connect();
                // Reaching here means the handshake succeeded — that is the intended assertion.
            }
            finally
            {
                conn.close();
                serverThread.join( 5_000L );
            }
        }
    }


    /**
     * Behavioural test using the {@link LdapConnectionConfig} constructor path.
     * Verifies that hostname verification is enforced when the connection is created via
     * {@link LdapNetworkConnection#LdapNetworkConnection(LdapConnectionConfig)}: the PKIX
     * TrustManager rejects the handshake because the server certificate CN
     * (wrong.host.invalid) does not match the configured host (localhost).
     */
    @Test
    public void testSslHandshakeRejectedWhenCertHostnameMismatchesViaLdapConnectionConfig() throws Exception
    {
        TrustManagerFactory tmf = buildPkixTrustManager();

        SSLServerSocketFactory ssf = serverSslContext.getServerSocketFactory();
        try ( SSLServerSocket serverSocket = ( SSLServerSocket ) ssf.createServerSocket( 0 ) )
        {
            serverSocket.setSoTimeout( 10_000 );
            int port = serverSocket.getLocalPort();
            Thread serverThread = startTlsServer( serverSocket, true );

            LdapConnectionConfig config = new LdapConnectionConfig();
            config.setUseSsl( true );
            config.setLdapHost( "localhost" );
            config.setLdapPort( port );
            config.setTrustManagers( tmf.getTrustManagers() );

            LdapNetworkConnection conn = new LdapNetworkConnection( config );
            conn.setTimeOut( 5_000L );
            try
            {
                assertThrows( LdapException.class, () -> conn.connect(),
                    "connect() must throw when the server certificate CN does not match 'localhost'" );
            }
            finally
            {
                conn.close();
                serverThread.join( 5_000L );
            }
        }
    }
}
