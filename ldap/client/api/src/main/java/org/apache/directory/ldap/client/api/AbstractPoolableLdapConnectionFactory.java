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


import java.lang.reflect.Constructor;

import org.apache.commons.pool.PoolableObjectFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An abstract class implementing the PoolableObjectFactory, for LdapConnections.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractPoolableLdapConnectionFactory implements PoolableObjectFactory<LdapConnection>
{
    /** This class logger */
    private static final Logger LOG = LoggerFactory.getLogger( AbstractPoolableLdapConnectionFactory.class );

    /** The factory to use to create a new connection */
    protected LdapConnectionFactory connectionFactory;

    /** The validator to use */
    protected LdapConnectionValidator validator = new LookupLdapConnectionValidator();

    /**
     * {@inheritDoc}
     * 
     * There is nothing to do to activate a connection.
     */
    @Override
    public void activateObject( LdapConnection connection ) throws LdapException
    {
        LOG.debug( "Activating {}", connection );
        if ( !connection.isConnected() || !connection.isAuthenticated() )
        {
            LOG.debug( "rebind due to connection dropped on {}", connection );
            connectionFactory.bindConnection( connection );
        }
    }


    /**
     * {@inheritDoc}
     * 
     * Destroying a connection will unbind it which will result on a shutdown
     * of teh underlying protocol.
     */
    @Override
    public void destroyObject( LdapConnection connection ) throws LdapException
    {
        LOG.debug( "Destroying {}", connection );

        try
        {
            // https://tools.ietf.org/html/rfc2251#section-4.3
            // unbind closes the connection so no need to close
            connection.unBind();
        }
        catch ( LdapException e )
        {
            LOG.error( "unable to unbind connection: {}", e.getMessage() );
            LOG.debug( "unable to unbind connection:", e );
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
     * Specifically, we are creating a new connection based on the LdapConnection Factory
     * we used to create this pool of connections. The default is to create bound connections.
     * 
     * @throws LdapException If unable to connect.
     */
    @Override
    public LdapConnection makeObject() throws LdapException
    {
        LOG.debug( "Creating a LDAP connection" );
        return connectionFactory.newLdapConnection();
    }


    protected static LdapConnectionFactory newLdapConnectionFactory(
        LdapConnectionConfig config,
        Class<? extends LdapConnectionFactory> connectionFactoryClass )
    {
        try
        {
            Constructor<? extends LdapConnectionFactory> constructor =
                connectionFactoryClass.getConstructor( LdapConnectionConfig.class );
            return constructor.newInstance( config );
        }
        catch ( Exception e )
        {
            throw new IllegalArgumentException( "unable to create LdapConnectionFactory" + e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     * 
     * We don't do anything with the connection. It remains in the state it was before
     * being used.
     * 
     * @throws LdapException If unable to reconfigure and rebind.
     */
    @Override
    public void passivateObject( LdapConnection connection ) throws LdapException
    {
        LOG.debug( "Passivating {}", connection );
    }
  
    
    /**
     * Sets the validator to use when validation occurs.  Note that validation
     * will only occur if the connection pool was configured to validate.  This
     * means one of:
     * <ul>
     * <li>{@link org.apache.commons.pool.impl.GenericObjectPool#setTestOnBorrow setTestOnBorrow}</li>
     * <li>{@link org.apache.commons.pool.impl.GenericObjectPool#setTestWhileIdle setTestWhileIdle}</li>
     * <li>{@link org.apache.commons.pool.impl.GenericObjectPool#setTestOnReturn setTestOnReturn}</li>
     * </ul>
     * must have been set to true on the pool.  The default validator is 
     * {@link LookupLdapConnectionValidator}.
     *
     * @param validator The validator
     */
    public void setValidator( LdapConnectionValidator validator ) 
    {
        this.validator = validator;
    }


    /**
     * {@inheritDoc}
     * 
     * Validating a connection is done by checking the connection status.
     */
    @Override
    public boolean validateObject( LdapConnection connection )
    {
        LOG.debug( "Validating {}", connection );
        return validator.validate( connection );
    }
}
