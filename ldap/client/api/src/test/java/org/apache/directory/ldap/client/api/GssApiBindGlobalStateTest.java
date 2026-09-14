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


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


/**
 * Tests that a GSSAPI bind does not leak process-global authentication state :
 * the JVM-wide JAAS {@link Configuration} must not be replaced, and the
 * 'java.security.krb5.conf' and 'javax.security.auth.useSubjectCredsOnly'
 * system properties must be restored after the bind attempt.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GssApiBindGlobalStateTest
{
    private static final String KRB5_CONF = "java.security.krb5.conf";
    private static final String USE_SUBJECT_CREDS_ONLY = "javax.security.auth.useSubjectCredsOnly";

    /** A sentinel JAAS Configuration, standing in for a co-resident application's configuration */
    private Configuration sentinelConfiguration;

    private String previousKrb5Conf;
    private String previousUseSubjectCredsOnly;


    @BeforeEach
    public void setUp()
    {
        previousKrb5Conf = System.getProperty( KRB5_CONF );
        previousUseSubjectCredsOnly = System.getProperty( USE_SUBJECT_CREDS_ONLY );

        System.setProperty( KRB5_CONF, "sentinel-krb5.conf" );
        System.setProperty( USE_SUBJECT_CREDS_ONLY, "false" );

        sentinelConfiguration = new Configuration()
        {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry( String name )
            {
                return null;
            }
        };

        Configuration.setConfiguration( sentinelConfiguration );
    }


    @AfterEach
    public void tearDown()
    {
        restore( KRB5_CONF, previousKrb5Conf );
        restore( USE_SUBJECT_CREDS_ONLY, previousUseSubjectCredsOnly );
        Configuration.setConfiguration( null );
    }


    private static void restore( String key, String previousValue )
    {
        if ( previousValue == null )
        {
            System.clearProperty( key );
        }
        else
        {
            System.setProperty( key, previousValue );
        }
    }


    /**
     * A GSSAPI bind attempt (here failing fast, as no KDC is reachable) must
     * leave the JVM-global JAAS Configuration and the Kerberos system
     * properties exactly as they were.
     *
     * @throws Exception If the test fails
     */
    @Test
    public void testGssApiBindDoesNotLeakGlobalState() throws Exception
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setLdapHost( "127.0.0.1" );
        config.setLdapPort( 389 );

        try ( LdapNetworkConnection connection = new LdapNetworkConnection( config ) )
        {
            SaslGssApiRequest request = new SaslGssApiRequest();
            request.setUsername( "user" );
            request.setCredentials( "secret" );
            
            // A krb5.conf path that does not exist : the login fails fast,
            // before any network access
            request.setKrb5ConfFilePath( "target/does-not-exist-krb5.conf" );

            assertThrows( LdapException.class, () ->
            {
                connection.bindAsync( request );
            } );
        }

        // The JVM-global JAAS Configuration must not have been replaced
        assertSame( sentinelConfiguration, Configuration.getConfiguration() );

        // The system properties must have been restored
        assertEquals( "sentinel-krb5.conf", System.getProperty( KRB5_CONF ) );
        assertEquals( "false", System.getProperty( USE_SUBJECT_CREDS_ONLY ) );
    }
}