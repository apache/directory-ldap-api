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


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Test;
import org.mockito.exceptions.misusing.NotAMockException;
import org.mockito.internal.util.MockUtil;
import org.mockito.verification.VerificationMode;


public class ValidatingPoolableLdapConnectionFactoryTest
{
    private static final String ADMIN_CREDENTIALS = "secret";
    private static final String ADMIN_DN = "uid=admin, ou=system";
    private static final MockUtil MOCK_UTIL = new MockUtil();


    @Test
    public void testPoolWithBind()
    {
        PoolTester tester = new PoolTester();

        // no bind
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind()
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.bind();
                    verify( connection, times( 1 ) ).bind();
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // anonymousBind()
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.anonymousBind();
                    verify( connection, times( 1 ) ).anonymousBind();
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind( String )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.bind( "" );
                    verify( connection, times( 1 ) ).bind( "" );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // admin bind( String, String )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.bind( ADMIN_DN, ADMIN_CREDENTIALS );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind( String, String )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.bind( "", "" );
                    verify( connection, times( 1 ) ).bind( "", "" );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind( Dn )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    Dn dn = new Dn();
                    connection.bind( dn );
                    verify( connection, times( 1 ) ).bind( dn );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind( Dn, String )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    Dn dn = new Dn();
                    connection.bind( dn, "" );
                    verify( connection, times( 1 ) ).bind( dn, "" );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // bind( BindRequest );
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    BindRequest bindRequest = new BindRequestImpl();
                    connection.bind( bindRequest );
                    verify( connection, times( 1 ) ).bind( bindRequest );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );
    }


    @Test
    public void testPoolWithStartTls()
    {
        PoolTester tester = new PoolTester();

        // extended( String )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.extended( StartTlsRequest.EXTENSION_OID );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // extended( String, byte[] )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.extended( StartTlsRequest.EXTENSION_OID, new byte[]
                        {} );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // extended( Oid )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    try
                    {
                        connection.extended( Oid.fromString( StartTlsRequest.EXTENSION_OID ) );
                    }
                    catch ( DecoderException e )
                    {
                        throw new IllegalArgumentException( "invalid oid: " + StartTlsRequest.EXTENSION_OID );
                    }
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // extended( Oid, byte[] )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    try
                    {
                        connection.extended( Oid.fromString( StartTlsRequest.EXTENSION_OID ), new byte[]
                            {} );
                    }
                    catch ( DecoderException e )
                    {
                        throw new IllegalArgumentException( "invalid oid: " + StartTlsRequest.EXTENSION_OID );
                    }
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );

        // extended( ExtendedRequest )
        tester.execute(
            new WithConnection()
            {
                @Override
                public void execute( LdapConnection connection, Counts counts ) throws LdapException
                {
                    connection.extended( new StartTlsRequestImpl() );
                    verifyAdminBind( connection, times( counts.adminBindCount ) );
                }
            } );
    }


    private static final void verifyAdminBind( LdapConnection connection, VerificationMode mode ) throws LdapException
    {
        verify( connection, mode ).bind( ADMIN_DN, ADMIN_CREDENTIALS );
    }


    private static final LdapConnection verify( LdapConnection connection, VerificationMode mode )
    {
        if ( MOCK_UTIL.isMock( connection ) )
        {
            return org.mockito.Mockito.verify( connection, mode );
        }
        else
        {
            if ( connection instanceof Wrapper )
            {
                @SuppressWarnings("unchecked")
                LdapConnection unwrapped = ( ( Wrapper<LdapConnection> ) connection ).wrapped();
                return verify( unwrapped, mode );
            }
        }
        throw new NotAMockException( "connection is not a mock, nor a wrapper for a connection that is one" );
    }

    private static final class Counts
    {
        private int adminBindCount = 0;
        private int unBindCount = 0;
    }

    public static final class InternalMonitoringLdapConnection extends LdapConnectionWrapper
    {
        private static final Oid START_TLS_OID;

        static
        {
            try
            {
                START_TLS_OID = Oid.fromString( StartTlsRequest.EXTENSION_OID );
            }
            catch ( DecoderException e )
            {
                throw new IllegalStateException( "StartTlsRequest.EXTENSION_OID is not a valid oid...  IMPOSSIBLE" );
            }
        }

        private int borrowedCount = 0;
        private boolean bindCalled = false;
        private Counts counts = new Counts();
        private boolean startTlsCalled = false;
        private boolean unBindCalled = false;


        InternalMonitoringLdapConnection( LdapConnection connection )
        {
            super( connection );
        }


        private int incrementBorrowedCount()
        {
            return ++borrowedCount;
        }


        public boolean bindCalled()
        {
            return bindCalled;
        }


        public void resetMonitors()
        {
            bindCalled = false;
            startTlsCalled = false;
            unBindCalled = false;
        }


        public boolean startTlsCalled()
        {
            return startTlsCalled;
        }


        public boolean unBindCalled()
        {
            return unBindCalled;
        }


        @Override
        public void bind() throws LdapException
        {
            connection.bind();
            bindCalled = true;
        }


        @Override
        public void anonymousBind() throws LdapException
        {
            connection.anonymousBind();
            bindCalled = true;
        }


        @Override
        public void bind( String name ) throws LdapException
        {
            connection.bind( name );
            bindCalled = true;
        }


        @Override
        public void bind( String name, String credentials ) throws LdapException
        {
            connection.bind( name, credentials );
            if ( ADMIN_DN.equals( name )
                && ADMIN_CREDENTIALS.equals( credentials ) )
            {
                counts.adminBindCount++;
            }
            bindCalled = true;
        }


        @Override
        public void bind( Dn name ) throws LdapException
        {
            connection.bind( name );
            bindCalled = true;
        }


        @Override
        public void bind( Dn name, String credentials ) throws LdapException
        {
            connection.bind( name, credentials );
            bindCalled = true;
        }


        @Override
        public BindResponse bind( BindRequest bindRequest ) throws LdapException
        {
            BindResponse response = connection.bind( bindRequest );
            bindCalled = true;
            return response;
        }


        @Override
        public ExtendedResponse extended( String oid ) throws LdapException
        {
            if ( StartTlsRequest.EXTENSION_OID.equals( oid ) )
            {
                startTlsCalled = true;
            }
            return connection.extended( oid );
        }


        @Override
        public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
        {
            if ( StartTlsRequest.EXTENSION_OID.equals( oid ) )
            {
                startTlsCalled = true;
            }
            return connection.extended( oid, value );
        }


        @Override
        public ExtendedResponse extended( Oid oid ) throws LdapException
        {
            if ( START_TLS_OID.equals( oid ) )
            {
                startTlsCalled = true;
            }
            return connection.extended( oid );
        }


        @Override
        public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
        {
            if ( START_TLS_OID.equals( oid ) )
            {
                startTlsCalled = true;
            }
            return connection.extended( oid, value );
        }


        @Override
        public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
        {
            if ( extendedRequest.hasControl( StartTlsRequest.EXTENSION_OID ) )
            {
                startTlsCalled = true;
            }
            return connection.extended( extendedRequest );
        }


        @Override
        public void unBind() throws LdapException
        {
            counts.unBindCount++;
            unBindCalled = true;
            connection.unBind();
        }
    }

    private static class PoolTester
    {
        private LdapConnectionConfig config;
        private LdapConnectionPool pool;
        private LdapConnectionValidator validator;


        public PoolTester()
        {
            LdapConnection mockConnection = mock( LdapConnection.class );
            when( mockConnection.isAuthenticated() ).thenReturn( true );
            when( mockConnection.isConnected() ).thenReturn( true );

            config = new LdapConnectionConfig();
            config.setName( ADMIN_DN );
            config.setCredentials( ADMIN_CREDENTIALS );

            MockLdapConnectionFactory mockConnectionFactory = new MockLdapConnectionFactory( config );
            mockConnectionFactory.addConnection(
                new InternalMonitoringLdapConnection( mockConnection ) );

            validator = mock( LdapConnectionValidator.class );
            when( validator.validate( any( LdapConnection.class ) ) ).thenReturn( true );
            ValidatingPoolableLdapConnectionFactory poolableFactory =
                new ValidatingPoolableLdapConnectionFactory( mockConnectionFactory );
            poolableFactory.setValidator( validator );

            pool = new LdapConnectionPool( poolableFactory );
            pool.setMaxActive( 1 );
            pool.setTestOnBorrow( true );
            pool.setTestOnReturn( true );
        }


        public void execute( WithConnection withConnection )
        {
            LdapConnection connection = null;
            InternalMonitoringLdapConnection internal = null;
            int borrowedCount = 0;
            try
            {
                connection = pool.getConnection();
                assertNotNull( connection );
                internal = ( InternalMonitoringLdapConnection ) ( ( LdapConnectionWrapper ) connection ).wrapped();
                borrowedCount = internal.incrementBorrowedCount();
                org.mockito.Mockito.verify( validator, times( 2 * borrowedCount - 1 ) ).validate( connection );
                internal.resetMonitors();

                withConnection.execute( connection, internal.counts );
            }
            catch ( LdapException e )
            {
                fail( "unable to getConnection(): " + e.getMessage() );
            }
            finally
            {
                try
                {
                    int adminBindCount = internal.counts.adminBindCount;
                    pool.releaseConnection( connection );
                    org.mockito.Mockito.verify( validator, times( 2 * borrowedCount ) ).validate( connection );

                    if ( internal.startTlsCalled() )
                    {
                        verify( connection, times( internal.counts.unBindCount ) ).unBind();
                    }

                    int expectedCount = internal.bindCalled() || internal.startTlsCalled() || internal.unBindCalled()
                        ? adminBindCount + 1
                        : adminBindCount;
                    verifyAdminBind( connection, times( expectedCount ) );
                }
                catch ( LdapException e )
                {
                    fail( "unable to releaseConnection(): " + e.getMessage() );
                }
            }
        }
    }

    private static interface WithConnection
    {
        /** 
         * Executes code using the supplied connection.
         * 
         * @param connection The ldap connection
         * @param counts The counters for specific calls
         */
        public void execute( LdapConnection connection, Counts counts ) throws LdapException;
    }
}
