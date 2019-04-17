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
package org.apache.directory.ldap.client.api;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.util.List;

import javax.net.ssl.X509TrustManager;

import org.apache.directory.api.ldap.codec.api.SchemaBinaryAttributeDetector;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Network;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;


/**
 * Test the LdapConnection class by enabling SSL and StartTLS one after the other
 * (using both in the same test class saves the time required to start/stop another server for StartTLS)
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */

public class LdapSSLConnectionTest
{
    private LdapConnectionConfig sslConfig;

    private LdapConnectionConfig tlsConfig;


    @Before
    public void setup() throws Exception
    {
        sslConfig = new LdapConnectionConfig();
        sslConfig.setLdapHost( Network.LOOPBACK_HOSTNAME );
        sslConfig.setUseSsl( true );
        sslConfig.setLdapPort( 10636 );
        sslConfig.setTrustManagers( new NoVerificationTrustManager() );
        sslConfig.setBinaryAttributeDetector( new SchemaBinaryAttributeDetector( null ) );

        tlsConfig = new LdapConnectionConfig();
        tlsConfig.setLdapHost( Network.LOOPBACK_HOSTNAME );
        tlsConfig.setLdapPort( 10389 );
        tlsConfig.setTrustManagers( new NoVerificationTrustManager() );
        tlsConfig.setBinaryAttributeDetector( new SchemaBinaryAttributeDetector( null ) );
    }


    /**
     * Test a successful bind request
     *
     * @throws IOException
     */
    @Test
    @Ignore
    public void testBindRequestSSLConfig() throws Exception
    {
        try ( LdapNetworkConnection connection = new LdapNetworkConnection( sslConfig ) )
        {
            connection.bind( "uid=admin,ou=system", "secret" );

            assertTrue( connection.getConfig().isUseSsl() );
            assertTrue( connection.isAuthenticated() );
            assertTrue( connection.isSecured() );
        }
    }


    /**
     * Test a successful bind request
     *
     * @throws IOException
     */
    @Test
    @Ignore
    public void testBindRequestSSLAuto() throws Exception
    {
        sslConfig.setTrustManagers( new X509TrustManager[] { new NoVerificationTrustManager() } );

        try ( LdapNetworkConnection connection = 
            new LdapNetworkConnection( sslConfig ) )
        {
            connection.bind( "uid=admin,ou=system", "secret" );
            assertTrue( connection.getConfig().isUseSsl() );

            assertTrue( connection.isAuthenticated() );
            assertTrue( connection.isSecured() );
        }
    }


    @Test
    @Ignore
    public void testGetSupportedControls() throws Exception
    {
        try ( LdapConnection connection = new LdapNetworkConnection( sslConfig ) )
        {    
            Dn dn = new Dn( "uid=admin,ou=system" );
            connection.bind( dn.getName(), "secret" );
    
            List<String> controlList = connection.getSupportedControls();
            assertNotNull( controlList );
            assertFalse( controlList.isEmpty() );
        }
    }


    /**
     * Test a successful bind request after setting up TLS
     *
     * @throws IOException
     */
    @Test
    @Ignore
    public void testStartTLSBindRequest() throws Exception
    {
        try ( LdapNetworkConnection connection = new LdapNetworkConnection( tlsConfig ) )
        {
            tlsConfig.setUseTls( true );
            connection.connect();

            connection.bind( "uid=admin,ou=system", "secret" );
            assertTrue( connection.isAuthenticated() );

            // try multiple binds with startTLS DIRAPI-173
            connection.bind( "uid=admin,ou=system", "secret" );
            assertTrue( connection.isAuthenticated() );
            
            connection.bind( "uid=admin,ou=system", "secret" );
            assertTrue( connection.isAuthenticated() );
            assertTrue( connection.isSecured() );

            connection.unBind();
        }
    }


    /**
     * Test a request before setting up TLS
     *
     * @throws IOException
     */
    @Test
    @Ignore
    public void testStartTLSAfterBind() throws Exception
    {
        tlsConfig.setTrustManagers( new X509TrustManager[] { new NoVerificationTrustManager() } );

        try ( LdapNetworkConnection connection = 
            new LdapNetworkConnection( tlsConfig ) )
        {
            connection.connect();

            connection.bind( "uid=admin,ou=system", "secret" );
            assertFalse( connection.isSecured() );

            Entry rootDse = connection.getRootDse( "*", "+" );
            
            assertNotNull( rootDse );

            // startTLS
            connection.startTls();
            
            // try multiple binds with startTLS DIRAPI-173
            assertTrue( connection.isSecured() );

            Entry admin = connection.lookup( "uid=admin,ou=system" );

            assertNotNull( admin );
            assertEquals( "uid=admin,ou=system", admin.getDn().getName() );

            connection.unBind();
        }
    }


    @Test
    @Ignore
    public void testGetSupportedControlsWithStartTLS() throws Exception
    {
        try ( LdapNetworkConnection connection = new LdapNetworkConnection( tlsConfig ) )
        {
            tlsConfig.setUseTls( true );
            connection.connect();
    
            Dn dn = new Dn( "uid=admin,ou=system" );
            connection.bind( dn.getName(), "secret" );
    
            List<String> controlList = connection.getSupportedControls();
            assertNotNull( controlList );
            assertFalse( controlList.isEmpty() );
        }
    }
}
