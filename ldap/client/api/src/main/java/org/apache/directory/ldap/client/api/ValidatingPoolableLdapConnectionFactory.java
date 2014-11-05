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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool. The connections are validated
 * before being returned, which leads to a round-trip to the server. It also re-bind the connection when
 * it's being put back to the pool, to reset the LDAPSession.
 * 
 * This is quite a costly - but secure - way to handle connections in a pool. If one would like to use a 
 * less expensive pool factory, the {@link DefaultPoolableLdapConnectionFactory} is most certainly a better
 * choice.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ValidatingPoolableLdapConnectionFactory extends AbstractPoolableLdapConnectionFactory
{
    /** This class logger */
    private static final Logger LOG = LoggerFactory.getLogger( ValidatingPoolableLdapConnectionFactory.class );


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param config the configuration for creating LdapConnections
     */
    public ValidatingPoolableLdapConnectionFactory( LdapConnectionConfig config )
    {
        this( new DefaultLdapConnectionFactory( config ) );
    }


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param connectionFactory the connection factory for creating LdapConnections
     */
    public ValidatingPoolableLdapConnectionFactory( LdapConnectionFactory connectionFactory )
    {
        this.connectionFactory = connectionFactory;
    }


    /**
     * {@inheritDoc}
     * 
     * There is nothing to do to activate a connection.
     */
    public void activateObject( LdapConnection connection )
    {
        LOG.debug( "Activating {}", connection );
    }


    /**
     * {@inheritDoc}
     * 
     * Destroying a connection will unbind it which will result on a shutdown
     * of teh underlying protocol.
     */
    public void destroyObject( LdapConnection connection )
    {
        LOG.debug( "Destroying {}", connection );

        if ( connection.isConnected() )
        {
            try
            {
                connection.unBind();
            }
            catch ( LdapException e )
            {
                LOG.error( "unable to unbind connection: {}", e.getMessage() );
                LOG.debug( "unable to unbind connection:", e );
            }
        }

        try
        {
            connection.close();
        }
        catch ( IOException e )
        {
            LOG.error( "unable to close connection: {}", e.getMessage() );
            LOG.debug( "unable to close connection:", e );
        }
    }


    /**
     * {@inheritDoc}
     * Specifically, we are creating a new connection based on the LdapConnection Factory
     * we used to create this pool of connections. The default is to create bound connections.
     * 
     * @throws LdapException If unable to connect.
     */
    public LdapConnection makeObject() throws LdapException
    {
        LOG.debug( "Creating a LDAP connection" );

        return connectionFactory.newLdapConnection();
    }


    /**
     * {@inheritDoc}
     * 
     * Here, passivating a connection means we re-bind it, so that the existing LDAPSession
     * is reset.
     * 
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
     * 
     * Validating a connection is done in depth : first we check that the connection is still
     * up, that the LdapSession is authenticated, and that we can retrieve some information 
     * from the server. If the connection is not authenticated, we re-bind.
     */
    public boolean validateObject( LdapConnection connection )
    {
        LOG.debug( "Validating {}", connection );

        if ( connection.isConnected() )
        {
            if ( connection.isAuthenticated() )
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
                // We have to bind the connection
                try
                {
                    connectionFactory.bindConnection( connection );

                    return true;
                }
                catch ( LdapException le )
                {
                    return false;
                }
            }
        }
        else
        {
            return false;
        }
    }
}
