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

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool. The connections are
 * not validated when they are pulled from the pool : we just check if they are still connected, using
 * their internal flag. We don't either re-bind when we push back teh connection into the pool.
 * <br/>
 * It's up to the users to be careful with the way they deal with connectiosn -especially when using
 * the StartTLS extended operation -.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultPoolableLdapConnectionFactory extends AbstractPoolableLdapConnectionFactory
{
    /** This class logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultPoolableLdapConnectionFactory.class );


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param config the configuration for creating LdapConnections
     */
    public DefaultPoolableLdapConnectionFactory( LdapConnectionConfig config )
    {
        this( new DefaultLdapConnectionFactory( config ) );
    }


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param connectionFactory the connection factory for creating LdapConnections
     */
    public DefaultPoolableLdapConnectionFactory( LdapConnectionFactory connectionFactory )
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
     * of the underlying protocol.
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
     * We don't do anything with the connection. It remains in the state it was before
     * being used.
     * 
     * @throws LdapException If unable to reconfigure and rebind.
     */
    public void passivateObject( LdapConnection connection ) throws LdapException
    {
        LOG.debug( "Passivating {}", connection );
    }


    /**
     * {@inheritDoc}
     * 
     * Validating a connection is done by checking the connection status. We though
     * re-bind if teh connection is connected but not authenticated.
     */
    public boolean validateObject( LdapConnection connection )
    {
        LOG.debug( "Validating {}", connection );

        if ( connection.isConnected() )
        {
            if ( connection.isAuthenticated() )
            {
                return true;
            }
            else
            {
                // Not authenticated, let's do it
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
            // Not connected, get out
            return false;
        }
    }
}
