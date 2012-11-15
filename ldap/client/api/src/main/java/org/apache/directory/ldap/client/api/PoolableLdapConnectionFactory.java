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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PoolableLdapConnectionFactory implements PoolableObjectFactory<LdapConnection>
{
    /** configuration object for the connection */
    private LdapConnectionConfig config;

    /** the logger */
    private static final Logger LOG = LoggerFactory.getLogger( PoolableLdapConnectionFactory.class );


    /**
     * 
     * Creates a new instance of PoolableLdapConnectionFactory for the
     * server running on localhost at the port 10389
     *
     * @param config the configuration for creating LdapConnections
     */
    public PoolableLdapConnectionFactory( LdapConnectionConfig config )
    {
        this.config = config;
    }


    /**
     * {@inheritDoc}
     */
    public void activateObject( LdapConnection connection ) throws Exception
    {
        LOG.debug( "Activating {}", connection );
    }


    /**
     * {@inheritDoc}
     */
    public void destroyObject( LdapConnection connection ) throws Exception
    {
        LOG.debug( "Destroying {}", connection );
        connection.unBind();
        connection.close();
    }


    /**
     * {@inheritDoc}
     */
    public LdapConnection makeObject() throws Exception
    {
        LOG.debug( "Creating a LDAP connection" );

        LdapNetworkConnection connection = new LdapNetworkConnection( config );
        
        try
        {
            connection.bind( config.getName(), config.getCredentials() );
        }
        catch ( Exception e )
        {
            // We weren't able to bind : close the connection
            connection.close();
            
            // And rethrow the exception
            throw e;
        }
        
        return connection;
    }


    /**
     * {@inheritDoc}
     */
    public void passivateObject( LdapConnection connection ) throws Exception
    {
        LOG.debug( "Passivating {}", connection );
    }


    /**
     * {@inheritDoc}
     */
    public boolean validateObject( LdapConnection connection )
    {
        LOG.debug( "Validating {}", connection );

        return connection.isConnected();
    }
}
