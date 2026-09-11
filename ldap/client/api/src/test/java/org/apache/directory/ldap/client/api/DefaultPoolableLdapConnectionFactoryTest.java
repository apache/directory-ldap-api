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


import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.junit.jupiter.api.Test;


/**
 * Tests that the connections handed out by {@link DefaultPoolableLdapConnectionFactory}
 * never leak the previous borrower's bind identity : a connection re-bound (or
 * StartTLS'ed) by a borrower is restored to the pool's configured identity when it
 * is returned to the pool.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultPoolableLdapConnectionFactoryTest
{
    private static final String ADMIN_CREDENTIALS = "secret";
    private static final String ADMIN_DN = "uid=admin, ou=system";


    private static LdapConnectionPool newPool( LdapConnection mockConnection )
    {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setName( ADMIN_DN );
        config.setCredentials( ADMIN_CREDENTIALS );

        MockLdapConnectionFactory connectionFactory = new MockLdapConnectionFactory( config );
        connectionFactory.addConnection( mockConnection );

        LdapConnectionPool pool = new LdapConnectionPool(
            new DefaultPoolableLdapConnectionFactory( connectionFactory ) );
        pool.setMaxTotal( 1 );

        return pool;
    }


    @Test
    public void testIdentityRestoredWhenBorrowerRebinds() throws Exception
    {
        LdapConnection mockConnection = mock( LdapConnection.class );
        when( mockConnection.isConnected() ).thenReturn( true );
        when( mockConnection.isAuthenticated() ).thenReturn( true );

        LdapConnectionPool pool = newPool( mockConnection );

        // makeObject() binds once with the pool identity
        LdapConnection connection = pool.getConnection();
        verify( mockConnection, times( 1 ) ).bind( ADMIN_DN, ADMIN_CREDENTIALS );

        // the borrower re-binds with another identity (e.g. credentials verification)
        connection.bind( "uid=mallory,ou=system", "melon" );
        verify( mockConnection, times( 1 ) ).bind( "uid=mallory,ou=system", "melon" );

        // returning the connection to the pool must restore the pool identity
        pool.releaseConnection( connection );
        verify( mockConnection, times( 2 ) ).bind( ADMIN_DN, ADMIN_CREDENTIALS );
    }


    @Test
    public void testNoRebindWhenIdentityUntouched() throws Exception
    {
        LdapConnection mockConnection = mock( LdapConnection.class );
        when( mockConnection.isConnected() ).thenReturn( true );
        when( mockConnection.isAuthenticated() ).thenReturn( true );

        LdapConnectionPool pool = newPool( mockConnection );

        LdapConnection connection = pool.getConnection();
        pool.releaseConnection( connection );

        // only the initial makeObject() bind : passivation stays cheap when the
        // borrower did not touch the connection identity
        verify( mockConnection, times( 1 ) ).bind( ADMIN_DN, ADMIN_CREDENTIALS );
        verify( mockConnection, never() ).unBind();
    }


    @Test
    public void testTlsStateClearedWhenBorrowerCalledStartTls() throws Exception
    {
        LdapConnection mockConnection = mock( LdapConnection.class );
        when( mockConnection.isConnected() ).thenReturn( true );
        when( mockConnection.isAuthenticated() ).thenReturn( true );

        LdapConnectionPool pool = newPool( mockConnection );

        LdapConnection connection = pool.getConnection();

        // the borrower secures the channel with a StartTLS extended operation
        connection.extended( StartTlsRequest.EXTENSION_OID );

        // returning the connection must clear the TLS layer and restore the identity
        pool.releaseConnection( connection );
        verify( mockConnection, times( 1 ) ).unBind();
        verify( mockConnection, times( 2 ) ).bind( ADMIN_DN, ADMIN_CREDENTIALS );
    }
}
