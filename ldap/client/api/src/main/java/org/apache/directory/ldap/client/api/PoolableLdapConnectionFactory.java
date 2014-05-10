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


import java.io.IOException;

import org.apache.commons.pool.PoolableObjectFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PoolableLdapConnectionFactory implements PoolableObjectFactory<LdapConnection>
{
    private static final Logger LOG = LoggerFactory.getLogger( PoolableLdapConnectionFactory.class );

    private LdapConnectionFactory connectionFactory;


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param config the configuration for creating LdapConnections
     */
    public PoolableLdapConnectionFactory( LdapConnectionConfig config )
    {
        this( new DefaultLdapConnectionFactory( config ) );
    }


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param connectionFactory the connection factory for creating LdapConnections
     */
    public PoolableLdapConnectionFactory( LdapConnectionFactory connectionFactory )
    {
        this.connectionFactory = connectionFactory;
    }


    /**
     * {@inheritDoc}
     */
    public void activateObject( LdapConnection connection )
    {
        LOG.debug( "Activating {}", connection );
    }


    /**
     * {@inheritDoc}
     */
    public void destroyObject( LdapConnection connection ) 
    {
        LOG.debug( "Destroying {}", connection );
        try {
            connection.unBind();
        }
        catch ( LdapException e ) {
            LOG.error( "unable to unbind connection: {}", e.getMessage() );
            LOG.debug( "unable to unbind connection:", e );
        }

        try {
            connection.close();
        }
        catch ( IOException e ) {
            LOG.error( "unable to close connection: {}", e.getMessage() );
            LOG.debug( "unable to close connection:", e );
        }
    }


    /**
     * Returns the LdapApiService instance used by this factory.
     *
     * @return The LdapApiService instance used by this factory
     */
    public LdapApiService getLdapApiService()
    {
        return connectionFactory.getLdapApiService();
    }


    /**
     * {@inheritDoc}
     * @throws LdapException If unable to connect.
     */
    public LdapConnection makeObject() throws LdapException
    {
        LOG.debug( "Creating a LDAP connection" );
        return connectionFactory.newLdapConnection();
    }


    /**
     * {@inheritDoc}
     * @throws LdapException If unable to reconfigure and rebind.
     */
    public void passivateObject( LdapConnection connection ) throws LdapException
    {
        LOG.debug( "Passivating {}", connection );
        
        // in case connection configuration was modified, or rebound to a
        // different identity, we reinitialize before returning to the pool.
        connectionFactory.bindConnection( 
            connectionFactory.configureConnection( connection ) );
    }


    /**
     * {@inheritDoc}
     */
    public boolean validateObject( LdapConnection connection )
    {
        LOG.debug( "Validating {}", connection );

        if ( connection.isConnected() )
        {
            try
            {
                return connection.lookup( Dn.ROOT_DSE, SchemaConstants.NO_ATTRIBUTE ) != null;
            }
            catch ( LdapException le )
            {
                return false;
            }
        }
        else
        {
            return false;
        }
    }
}
