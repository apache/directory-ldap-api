/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.util.Network;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class to hold the configuration for creating an LdapConnection.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapConnectionConfig
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( LdapConnectionConfig.class );

    /** Default ports for LDAP */
    public static final int DEFAULT_LDAP_PORT = 389;

    /** Default port for LDAPS */
    public static final int DEFAULT_LDAPS_PORT = 636;

    /** The default host : localhost */
    public static final String DEFAULT_LDAP_HOST = "localhost";

    /** The LDAP version */
    public static final int LDAP_V3 = 3;

    /** The default timeout for operation : 30 seconds */
    public static final long DEFAULT_TIMEOUT = 30000L;

    /** the default protocol used for creating SSL context */
    public static final String DEFAULT_SSL_PROTOCOL = "TLS";

    // --- private members ----
    /** A flag indicating if we are using SSL or not, default value is false */
    private boolean useSsl = false;

    /** The session timeout in milliseconds */
    private long timeout = DEFAULT_TIMEOUT;

    /** Timeout for connect and bind operations */
    private Long connectTimeout;

    /** Timeout for write operations (add, modify, delete, ...) */
    private Long writeOperationTimeout;

    /** Timeout for read operations (search, compare) */
    private Long readOperationTimeout;

    /** Timeout for close and unbind operations */
    private Long closeTimeout;

    /** Timeout for I/O (TCP) writes */
    private Long sendTimeout;

    /** A flag indicating if we are using TLS or not, default value is false */
    private boolean useTls = false;

    /** The selected LDAP port */
    private int ldapPort;

    /** the remote LDAP host */
    private String ldapHost;

    /** a valid Dn to authenticate the user */
    private String name;

    /** user's credentials ( current implementation supports password only); it must be a non-null value */
    private String credentials;

    /** an array of key managers, if set, will be used while initializing the SSL context */
    private KeyManager[] keyManagers;

    /** an instance of SecureRandom, if set, will be used while initializing the SSL context */
    private SecureRandom secureRandom;

    /** an array of certificate trust managers, if set, will be used while initializing the SSL context */
    private TrustManager[] trustManagers;

    /** an array of cipher suites which are enabled, if set, will be used while initializing the SSL context */
    private String[] enabledCipherSuites;

    /** an array of protocols which are enabled, if set, will be used while initializing the SSL context */
    private String[] enabledProtocols;

    /** name of the protocol used for creating SSL context, default value is "TLS" */
    private String sslProtocol = DEFAULT_SSL_PROTOCOL;

    /** The class used to detect if an attribute is HR or not */
    private BinaryAttributeDetector binaryAttributeDetector;

    /** The Service to use internally when creating connections */
    private LdapApiService ldapApiService;


    /**
     * Creates a default LdapConnectionConfig instance
     */
    public LdapConnectionConfig()
    {
        setDefaultTrustManager();
    }


    /**
     * Sets the default trust manager based on the SunX509 trustManagement algorithm
     **/
    private void setDefaultTrustManager()
    {
        String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        
        try
        {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance( defaultAlgorithm );
            tmf.init( ( KeyStore ) null );
            trustManagers = tmf.getTrustManagers();
        }
        catch ( KeyStoreException kse )
        {
            LOG.error( I18n.err( I18n.ERR_04172_KEYSTORE_INIT_FAILURE ) );
            throw new RuntimeException( kse.getMessage(), kse );
        }
        catch ( NoSuchAlgorithmException nsae )
        {
            LOG.error( I18n.err( I18n.ERR_04173_ALGORITHM_NOT_FOUND, defaultAlgorithm ) );
            throw new RuntimeException( nsae.getMessage(), nsae );
        }
    }


    /**
     * Checks if SSL (ldaps://) is used.
     *
     * @return true, if SSL is used
     */
    public boolean isUseSsl()
    {
        return useSsl;
    }


    /**
     * Sets whether SSL should be used.
     *
     * @param useSsl true to use SSL
     */
    public void setUseSsl( boolean useSsl )
    {
        this.useSsl = useSsl;
    }


    /**
     * Gets the LDAP port.
     *
     * @return the LDAP port
     */
    public int getLdapPort()
    {
        return ldapPort;
    }


    /**
     * Sets the LDAP port.
     *
     * @param ldapPort the new LDAP port
     */
    public void setLdapPort( int ldapPort )
    {
        this.ldapPort = ldapPort;
    }


    /**
     * Gets the LDAP host.
     *
     * @return the LDAP host
     */
    public String getLdapHost()
    {
        return ldapHost;
    }


    /**
     * Sets the LDAP host.
     *
     * @param ldapHost the new LDAP host
     */
    public void setLdapHost( String ldapHost )
    {
        this.ldapHost = ldapHost;
    }


    /**
     * Gets the name that is used to authenticate the user.
     *
     * @return the name
     */
    public String getName()
    {
        return name;
    }


    /**
     * Sets the name which is used to authenticate the user.
     *
     * @param name the new name
     */
    public void setName( String name )
    {
        this.name = name;
    }


    /**
     * Gets the credentials.
     *
     * @return the credentials
     */
    public String getCredentials()
    {
        return credentials;
    }


    /**
     * Sets the credentials.
     *
     * @param credentials the new credentials
     */
    public void setCredentials( String credentials )
    {
        this.credentials = credentials;
    }


    /**
     * Gets the default LDAP port.
     *
     * @return the default LDAP port
     */
    public int getDefaultLdapPort()
    {
        return DEFAULT_LDAP_PORT;
    }


    /**
     * Gets the default LDAPS port.
     *
     * @return the default LDAPS port
     */
    public int getDefaultLdapsPort()
    {
        return DEFAULT_LDAPS_PORT;
    }


    /**
     * Gets the default LDAP host.
     *
     * @return the default LDAP host
     */
    public String getDefaultLdapHost()
    {
        return Network.LOOPBACK_HOSTNAME;
    }


    /**
     * Gets the default timeout in milliseconds.
     *
     * @return the default timeout in milliseconds
     */
    public long getDefaultTimeout()
    {
        return DEFAULT_TIMEOUT;
    }


    /**
     * Gets the timeout in milliseconds.
     * This is a "global" timeout.
     * It is used when operation-specific timeouts are not specified.
     * It is also used for extended operations.
     *
     * @return the timeout in milliseconds
     */
    public long getTimeout()
    {
        return timeout;
    }


    /**
     * Sets the timeout in milliseconds.
     * This is a "global" timeout.
     * It is used when operation-specific timeouts are not specified.
     * It is also used for extended operations.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setTimeout( long timeout )
    {
        if ( timeout == -1L )
        {
            this.timeout = Long.MAX_VALUE;
        }
        else
        {
            this.timeout = timeout;
        }
    }
    

    /**
     * Gets connect timeout in milliseconds.
     * Connect timeout is applied to connect and bind operations.
     * If not specified, global timeout setting is applied.
     *
     * @return the timeout in milliseconds
     */
    public Long getConnectTimeout()
    {
        return connectTimeout;
    }
    

    /**
     * Sets connect timeout in milliseconds.
     * Connect timeout is applied to connect and bind operations.
     * If not specified, global timeout setting is applied.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setConnectTimeout( Long timeout )
    {
        if ( timeout == -1L )
        {
            this.connectTimeout = Long.MAX_VALUE;
        }
        else
        {
            this.connectTimeout = timeout;
        }
    }
    

    /**
     * Gets write operation timeout in milliseconds.
     * Write operation timeout is applied to operations that write data, such as add, modify and delete.
     * If not specified, global timeout setting is applied.
     *
     * @return the timeout in milliseconds
     */
    public Long getWriteOperationTimeout()
    {
        return writeOperationTimeout;
    }
    

    /**
     * Sets write operation timeout in milliseconds.
     * Write operation timeout is applied to operations that write data, such as add, modify and delete.
     * If not specified, global timeout setting is applied.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setWriteOperationTimeout( Long timeout )
    {
        if ( timeout == -1L )
        {
            this.writeOperationTimeout = Long.MAX_VALUE;
        }
        else
        {
            this.writeOperationTimeout = timeout;
        }
    }
    

    /**
     * Gets read operation timeout in milliseconds.
     * This timeout is applied to read operations, such as search and compare.
     * If not specified, global timeout setting is applied.
     *
     * @return the timeout in milliseconds
     */
    public Long getReadOperationTimeout()
    {
        return readOperationTimeout;
    }
    

    /**
     * Sets read operation timeout in milliseconds.
     * This timeout is applied to read operations, such as search and compare.
     * If not specified, global timeout setting is applied.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setReadOperationTimeout( Long timeout )
    {
        if ( timeout == -1L )
        {
            this.readOperationTimeout = Long.MAX_VALUE;
        }
        else
        {
            this.readOperationTimeout = timeout;
        }
    }
    

    /**
     * Gets close timeout in milliseconds.
     * Close timeout is applied to close and unbind operations.
     * If not specified, global timeout setting is applied.
     *
     * @return the timeout in milliseconds
     */
    public Long getCloseTimeout()
    {
        return closeTimeout;
    }


    /**
     * Sets close timeout in milliseconds.
     * Close timeout is applied to close and unbind operations.
     * If not specified, global timeout setting is applied.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setCloseTimeout( Long timeout )
    {
        if ( timeout == -1L )
        {
            this.closeTimeout = Long.MAX_VALUE;
        }
        else
        {
            this.closeTimeout = timeout;
        }
    }

    
    /**
     * Gets send timeout in milliseconds.
     * Send timeout is used for I/O (TCP) write operations.
     * If not specified, global timeout setting is applied.
     *
     * @return the timeout in milliseconds
     */
    public Long getSendTimeout()
    {
        return sendTimeout;
    }


    /**
     * Sets the send timeout in milliseconds.
     * Send timeout is used for I/O (TCP) write operations.
     * If not specified, global timeout setting is applied.
     *
     * @param timeout the timeout in milliseconds to set. If &lt; 0, will be set to infinite
     */
    public void setSendTimeout( Long timeout )
    {
        if ( timeout == -1L )
        {
            this.sendTimeout = Long.MAX_VALUE;
        }
        else
        {
            this.sendTimeout = timeout;
        }
    }


    /**
     * Gets the supported LDAP version.
     *
     * @return the supported LDAP version
     */
    public int getSupportedLdapVersion()
    {
        return LDAP_V3;
    }


    /**
     * Gets the trust managers.
     *
     * @return the trust managers
     */
    public TrustManager[] getTrustManagers()
    {
        return trustManagers;
    }


    /**
     * Sets the trust managers.
     *
     * @param trustManagers the new trust managers
     * @throws IllegalArgumentException if the trustManagers parameter is null or empty
     */
    public void setTrustManagers( TrustManager... trustManagers )
    {
        if ( ( trustManagers == null ) || ( trustManagers.length == 0 )
            || ( trustManagers.length == 1 && trustManagers[0] == null ) )
        {
            throw new IllegalArgumentException( "TrustManagers must not be null or empty" );
        }
        this.trustManagers = trustManagers;
    }


    /**
     * Gets the SSL protocol.
     *
     * @return the SSL protocol
     */
    public String getSslProtocol()
    {
        return sslProtocol;
    }


    /**
     * Sets the SSL protocol.
     *
     * @param sslProtocol the new SSL protocol
     */
    public void setSslProtocol( String sslProtocol )
    {
        this.sslProtocol = sslProtocol;
    }


    /**
     * Gets the key managers.
     *
     * @return the key managers
     */
    public KeyManager[] getKeyManagers()
    {
        return keyManagers;
    }


    /**
     * Sets the key managers.
     *
     * @param keyManagers the new key managers
     */
    public void setKeyManagers( KeyManager[] keyManagers )
    {
        this.keyManagers = keyManagers;
    }


    /**
     * Gets the secure random.
     *
     * @return the secure random
     */
    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }


    /**
     * Sets the secure random.
     *
     * @param secureRandom the new secure random
     */
    public void setSecureRandom( SecureRandom secureRandom )
    {
        this.secureRandom = secureRandom;
    }


    /**
     * Gets the cipher suites which are enabled.
     * 
     * @return the cipher suites which are enabled
     */
    public String[] getEnabledCipherSuites()
    {
        return enabledCipherSuites;
    }


    /**
     * Sets the cipher suites which are enabled
     * 
     * @param enabledCipherSuites the cipher suites which are enabled
     */
    public void setEnabledCipherSuites( String[] enabledCipherSuites )
    {
        this.enabledCipherSuites = enabledCipherSuites;
    }


    /**
     * Gets the protocols which are enabled.
     * 
     * @return the protocol which are enabled
     */
    public String[] getEnabledProtocols()
    {
        return enabledProtocols;
    }


    /**
     * Sets the protocols which are enabled
     * 
     * @param enabledProtocols the protocols which are enabled
     */
    public void setEnabledProtocols( String... enabledProtocols )
    {
        this.enabledProtocols = enabledProtocols;
    }


    /**
     * @return the binaryAttributeDetector
     */
    public BinaryAttributeDetector getBinaryAttributeDetector()
    {
        return binaryAttributeDetector;
    }


    /**
     * @param binaryAttributeDetector the binaryAttributeDetector to set
     */
    public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetector )
    {
        this.binaryAttributeDetector = binaryAttributeDetector;
    }


    /**
     * Checks if TLS is used.
     *
     * @return true, if TLS is used
     */
    public boolean isUseTls()
    {
        return useTls;
    }


    /**
     * Sets whether TLS should be used.
     *
     * @param useTls true to use TLS
     */
    public void setUseTls( boolean useTls )
    {
        this.useTls = useTls;
    }


    /**
     * @return the ldapApiService
     */
    public LdapApiService getLdapApiService()
    {
        return ldapApiService;
    }


    /**
     * @param ldapApiService the ldapApiService to set
     */
    public void setLdapApiService( LdapApiService ldapApiService )
    {
        this.ldapApiService = ldapApiService;
    }
}
