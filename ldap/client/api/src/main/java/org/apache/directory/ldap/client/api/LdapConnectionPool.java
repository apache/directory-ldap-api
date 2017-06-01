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


import org.apache.commons.pool.PoolableObjectFactory;
import org.apache.commons.pool.impl.GenericObjectPool;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A pool implementation for LdapConnection objects.
 * 
 * This class is just a wrapper around the commons GenericObjectPool, and has
 * a more meaningful name to represent the pool type.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapConnectionPool extends GenericObjectPool<LdapConnection>
{
    private static final Logger LOG = LoggerFactory.getLogger( LdapConnectionPool.class );

    private PoolableObjectFactory<LdapConnection> factory;


    /**
     * Instantiates a new LDAP connection pool.
     *
     * @param connectionConfig The connection configuration
     * @param apiService The api service (codec)
     * @param timeout The connection timeout in millis
     */
    public LdapConnectionPool( LdapConnectionConfig connectionConfig,
        LdapApiService apiService, long timeout )
    {
        this( connectionConfig, apiService, timeout, null );
    }


    /**
     * Instantiates a new LDAP connection pool.
     *
     * @param connectionConfig The connection configuration
     * @param apiService The api service (codec)
     * @param timeout The connection timeout in millis
     * @param poolConfig The pool configuration
     */
    public LdapConnectionPool( LdapConnectionConfig connectionConfig,
        LdapApiService apiService, long timeout, Config poolConfig )
    {
        this( newPoolableConnectionFactory( connectionConfig, apiService, timeout ), poolConfig );
    }


    /**
     * Instantiates a new LDAP connection pool.
     *
     * @param factory The LDAP connection factory
     */
    public LdapConnectionPool( PoolableObjectFactory<LdapConnection> factory )
    {
        this( factory, null );
    }


    /**
     * Instantiates a new LDAP connection pool.
     *
     * @param factory The LDAP connection factory
     * @param poolConfig The pool configuration
     */
    public LdapConnectionPool( PoolableObjectFactory<LdapConnection> factory, Config poolConfig )
    {
        super( factory, poolConfig == null ? new Config() : poolConfig );
        this.factory = factory;
    }


    /**
     * Returns the LdapApiService instance used by this connection pool.
     *
     * @return The LdapApiService instance used by this connection pool.
     */
    public LdapApiService getLdapApiService()
    {
        return ( ( AbstractPoolableLdapConnectionFactory ) factory ).getLdapApiService();
    }


    /**
     * Gives a LdapConnection fetched from the pool.
     *
     * @return an LdapConnection object from pool
     * @throws LdapException if an error occurs while obtaining a connection from the factory
     */
    public LdapConnection getConnection() throws LdapException
    {
        LdapConnection connection;

        try
        {
            connection = super.borrowObject();
            LOG.trace( "borrowed connection {}", connection );
        }
        catch ( LdapException | RuntimeException e )
        {
            throw e;
        }
        catch ( Exception e )
        {
            // wrap in runtime, but this should NEVER happen per published 
            // contract as it only throws what the makeObject throws and our 
            // PoolableLdapConnectionFactory only throws LdapException
            LOG.error( "An unexpected exception was thrown: ", e );
            throw new RuntimeException( e );
        }

        return connection;
    }


    private static ValidatingPoolableLdapConnectionFactory newPoolableConnectionFactory(
        LdapConnectionConfig connectionConfig, LdapApiService apiService,
        long timeout )
    {
        DefaultLdapConnectionFactory connectionFactory =
            new DefaultLdapConnectionFactory( connectionConfig );
        connectionFactory.setLdapApiService( apiService );
        connectionFactory.setTimeOut( timeout );
        return new ValidatingPoolableLdapConnectionFactory( connectionFactory );
    }


    /**
     * Places the given LdapConnection back in the pool.
     * 
     * @param connection the LdapConnection to be released
     * @throws LdapException if an error occurs while releasing the connection
     */
    public void releaseConnection( LdapConnection connection ) throws LdapException
    {
        try
        {
            super.returnObject( connection );
            LOG.trace( "returned connection {}", connection );
        }
        catch ( LdapException | RuntimeException e )
        {
            throw e;
        }
        catch ( Exception e )
        {
            // wrap in runtime, but this should NEVER happen as it only throws 
            // what the passivateObject throws and our 
            // PoolableLdapConnectionFactory only throws LdapException
            LOG.error( "An unexpected exception was thrown: ", e );
            throw new RuntimeException( e );
        }
    }
}
