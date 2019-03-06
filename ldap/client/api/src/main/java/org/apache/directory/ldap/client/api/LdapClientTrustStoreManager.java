/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.api;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


/**
 * Implement the X509TrustManager interface which will be used during JSSE truststore manager initialisation for LDAP
 * client-to-server communications over TLS/SSL.
 * It is used during certificate validation operations within JSSE.
 *
 * Note: This class allows self-signed certificates to pass the validation checks.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapClientTrustStoreManager implements X509TrustManager, Serializable
{
    /** Default serialVersionUID */
    private static final long serialVersionUID = 1L;
    
    // Logging
    private static final String CLS_NM = LdapClientTrustStoreManager.class.getName();
    private static final Logger LOG = LoggerFactory.getLogger( CLS_NM );

    // Config variables
    private boolean isExamineValidityDates;
    private char[] trustStorePw;
    
    // This is found on the classpath if trust.store.onclasspath = true (default), otherwise must include exact location on filepath:
    private String trustStoreFile;
    private String trustStoreFormat;
    
    private X509TrustManager[] x509TrustManagers;


    /**
     * Constructor used by connection configuration utility to load trust store manager.
     *
     * @param trustStoreFile    contains name of trust store file.
     * @param trustStorePw      contains the password for trust store
     * @param trustStoreFormat  contains the format for trust store
     * @param isExamineValidity boolean var determines if certificate will be examined for valid dates on load.
     */
    public LdapClientTrustStoreManager( String trustStoreFile, char[] trustStorePw,
        String trustStoreFormat, boolean isExamineValidity )
    {
        if ( trustStoreFile == null )
        {
            // Cannot continue, throw an unchecked exception:
            throw new RuntimeException( "LdapClientTrustStoreManager constructor : input file name is null" );
        }
        
        // contains the file name of a valid JSSE TrustStore found on classpath:
        this.trustStoreFile = trustStoreFile;
        
        // the password to the JSSE TrustStore:
        this.trustStorePw = trustStorePw.clone();
        
        // If true, verify the current date is within the validity period for every certificate in the TrustStore:
        this.isExamineValidityDates = isExamineValidity;
        
        if ( trustStoreFormat == null )
        {
            this.trustStoreFormat = KeyStore.getDefaultType();
        }
        else
        {
            this.trustStoreFormat = trustStoreFormat;
        }
    }


    /**
     * Determine if client certificate is to be trusted.
     *
     * @param x509Chain The certificate chain
     * @param authNType The key exchange algorithm being used
     * @throws CertificateException If the trustManager cannot be found 
     */
    public synchronized void checkClientTrusted( X509Certificate[] x509Chain, String authNType ) throws CertificateException
    {
        // For each certificate in the chain, check validity:
        for ( X509TrustManager trustMgr : getTrustManagers( x509Chain ) )
        {
            trustMgr.checkClientTrusted( x509Chain, authNType );
        }
    }


    /**
     * Determine if server certificate is to be trusted.
     *
     * @param x509Chain The certificate chain
     * @param authNType The key exchange algorithm being used
     * @throws CertificateException If the trustManager cannot be found 
     */
    public synchronized void checkServerTrusted( X509Certificate[] x509Chain, String authNType ) throws
        CertificateException
    {
        for ( X509TrustManager trustManager : getTrustManagers( x509Chain ) )
        {
            trustManager.checkServerTrusted( x509Chain, authNType );
        }
    }


    /**
     * Return the list of accepted issuers for this trust manager.
     *
     * @return array of accepted issuers
     */
    public synchronized X509Certificate[] getAcceptedIssuers()
    {
        List<X509Certificate> certificates = new ArrayList<>();
        
        for ( X509TrustManager trustManager : x509TrustManagers )
        {
            for ( X509Certificate certificate : trustManager.getAcceptedIssuers() )
            { 
                certificates.add( certificate );
            }
        }
            
        return certificates.toArray( new X509Certificate[]{} );
    }


    /**
     * Return array of trust managers to caller.  Will verify that current date is within certs validity period.
     *
     * @param x509Chain contains input X.509 certificate chain.
     * @return array of X.509 trust managers.
     * @throws CertificateException if trustStoreFile instance variable is null.
     */
    private synchronized X509TrustManager[] getTrustManagers( X509Certificate[] x509Chain ) throws
        CertificateException
    {
        if ( LOG.isInfoEnabled() )
        {            
            LOG.info( CLS_NM + ".getTrustManagers on classpath" );
        }
        
        return getTrustManagersOnClasspath( x509Chain );
    }


    /**
     * Return array of trust managers to caller.  Will verify that current date is within certs validity period.
     *
     * @param x509Chain contains input X.509 certificate chain.
     * @return array of X.509 trust managers.
     * @throws CertificateException if trustStoreFile instance variable is null.
     */
    private synchronized X509TrustManager[] getTrustManagersOnClasspath( X509Certificate[] x509Chain ) throws
        CertificateException
    {
        // If true, verify the current date is within each certificates validity period.
        if ( isExamineValidityDates )
        {
            Date currentDate = new Date();
            
            for ( X509Certificate x509Cert : x509Chain )
            {
                x509Cert.checkValidity( currentDate );
            }
        }
        
        InputStream trustStoreInputStream;
        
        if ( trustStoreFile != null )
        {
            try
            {
                trustStoreInputStream = new FileInputStream( trustStoreFile );
            }
            catch ( IOException ioe )
            {
                throw new CertificateException( "TrustStoreFile : file not found" );
            }
        }
        else
        {
            trustStoreInputStream = getTrustStoreInputStream();
        }
       
        if ( trustStoreInputStream == null )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.getTrustManagers : file not found" );
        }
        try
        {
            trustStoreInputStream.close();
        }
        catch ( IOException e )
        {
            // Eat this ioexception because it shouldn't be a problem, but log just in case:
            LOG.warn( "LdapClientTrustStoreManager.getTrustManagers on input stream close "
                    + "operation caught IOException={}", e.getMessage() );
        }
        
        return loadTrustManagers( getTrustStore() );
    }


    /**
     * Return an array of X.509 TrustManagers.
     *
     * @param trustStore handle to input trustStore
     * @return array of trust managers
     * @throws CertificateException if problem occurs during TrustManager initialization.
     */
    private X509TrustManager[] loadTrustManagers( KeyStore trustStore ) throws CertificateException
    {
        try
        {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance( TrustManagerFactory
                .getDefaultAlgorithm() );
            trustManagerFactory.init( trustStore );
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            x509TrustManagers = new X509TrustManager[trustManagers.length];
            
            for ( int i = 0; i < trustManagers.length; i++ )
            {
                x509TrustManagers[i] = ( X509TrustManager ) trustManagers[i];
            }
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.loadTrustManagers caught "
                + "NoSuchAlgorithmException", e );
        }
        catch ( KeyStoreException e )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.loadTrustManagers caught KeyStoreException", e );
        }
        
        return x509TrustManagers;
    }


    /**
     * Load the TrustStore file into JSSE KeyStore instance.
     *
     * @return instance of JSSE KeyStore containing the LDAP Client's TrustStore file info.     *
     * @throws CertificateException if cannot process file load.
     */
    private KeyStore getTrustStore() throws CertificateException
    {
        KeyStore trustStore;
        
        try
        {
            trustStore = KeyStore.getInstance( trustStoreFormat );
        }
        catch ( KeyStoreException e )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.getTrustManagers caught KeyStoreException", e );
        }
        
        InputStream trustStoreInputStream = null;
        
        try
        {
            if ( trustStoreFile != null )
            {
                trustStoreInputStream = new FileInputStream( trustStoreFile );
            }
            else
            {
                trustStoreInputStream = getTrustStoreInputStream();
            }
            
            trustStore.load( trustStoreInputStream, trustStorePw );
        }
        catch ( NoSuchAlgorithmException e )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.getTrustManagers caught "
                + "NoSuchAlgorithmException", e );
        }
        catch ( IOException e )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.getTrustManagers caught KeyStoreException", e );
        }
        finally
        {
            // Close the input stream.
            if ( trustStoreInputStream != null )
            {
                try
                {
                    trustStoreInputStream.close();
                }
                catch ( IOException e )
                {
                    // Eat this ioexception because it shouldn't be a problem, but log just in case:
                    LOG.warn( "LdapClientTrustStoreManager.getTrustStore finally block on input stream close "
                        + "operation caught IOException={}", e.getMessage() );
                }
            }
        }
        
        return trustStore;
    }


    /**
     * Read the trust store off the classpath.
     *
     * @return handle to inputStream containing the trust store
     * @throws CertificateException If the file cannot be found
     */
    private InputStream getTrustStoreInputStream() throws CertificateException
    {
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        InputStream result = classloader.getResourceAsStream( trustStoreFile );
        
        if ( null == result )
        {
            throw new CertificateException( "LdapClientTrustStoreManager.getTrustStoreInputStream file does not exist on fortress classpath" );
        }
        
        return result;
    }
}
