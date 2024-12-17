/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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

import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.PooledObjectFactory;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An abstract class implementing the PoolableObjectFactory, for LdapConnections.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractPoolableLdapConnectionFactory implements PooledObjectFactory<LdapConnection>
{
    /** This class logger */
    private static final Logger LOG = LoggerFactory.getLogger( AbstractPoolableLdapConnectionFactory.class );

    /** The factory to use to create a new connection */
    protected LdapConnectionFactory connectionFactory;

    /** The validator to use */
    protected LdapConnectionValidator validator = new LookupLdapConnectionValidator();

    /** A internal class to wrap a standard LDAP connection */ 
    private static class PooledLdapConnectionFactory implements LdapConnectionFactory
    {
        private final LdapConnectionFactory delegate;

        private final LdapConnectionPool connectionPool;

        PooledLdapConnectionFactory( LdapConnectionFactory delegate, LdapConnectionPool connectionPool )
        {
            this.delegate = delegate;
            this.connectionPool = connectionPool;
        }


        private LdapConnection wrap( LdapConnection ldapConnection )
        {
            if ( ldapConnection instanceof PooledLdapConnection )
            {
                return ldapConnection;
            }

            return new PooledLdapConnection( ldapConnection, connectionPool );
        }


        @Override
        public LdapConnection bindConnection( LdapConnection connection ) throws LdapException
        {
            return wrap( delegate.bindConnection( connection ) );
        }


        @Override
        public LdapConnection configureConnection( LdapConnection connection )
        {
            return wrap( delegate.configureConnection( connection ) );
        }


        @Override
        public LdapApiService getLdapApiService()
        {
            return delegate.getLdapApiService();
        }


        @Override
        public LdapConnection newLdapConnection() throws LdapException
        {
            return wrap( delegate.newLdapConnection() );
        }


        @Override
        public LdapConnection newUnboundLdapConnection()
        {
            return wrap( delegate.newUnboundLdapConnection() );
        }
    }
    
    
    /**
     * Constructor that takes a LdapConnection factory for poolable connections
     * 
     * @param connectionFactory The Ldap connection factory to use
     */
    public AbstractPoolableLdapConnectionFactory( LdapConnectionFactory connectionFactory )
    {
        this.connectionFactory = connectionFactory;
    }

    
    void configurePooledLdapConnectionFactory( LdapConnectionPool connectionPool )
    {
        this.connectionFactory = new PooledLdapConnectionFactory( connectionFactory, connectionPool );
    }
    
    
    /**
     * {@inheritDoc}
     * 
     * There is nothing to do to activate a connection.
     */
    @Override
    public void activateObject( PooledObject<LdapConnection> connection ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04146_ACTIVATING, connection ) );
        }
        
        if ( !connection.getObject().isConnected() || !connection.getObject().isAuthenticated() )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04147_REBIND_CONNECTION_DROPPED, connection ) );
            }
            
            connectionFactory.bindConnection( connection.getObject() );
        }
    }


    /**
     * {@inheritDoc}
     * 
     * Destroying a connection will unbind it which will result on a shutdown
     * of teh underlying protocol.
     */
    @Override
    public void destroyObject( PooledObject<LdapConnection> connection ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04148_DESTROYING, connection ) );
        }

        try
        {
            // https://tools.ietf.org/html/rfc2251#section-4.3
            // unbind closes the connection so no need to close
            connection.getObject().unBind();
        }
        catch ( LdapException e )
        {
            LOG.error( I18n.err( I18n.ERR_04100_UNABLE_TO_UNBIND, e.getMessage() ) );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04149_UNABLE_TO_UNBIND, e.getMessage() ) );
            }
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
    public PooledObject<LdapConnection> makeObject() throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04150_CREATING_LDAP_CONNECTION ) );
        }
        
        return new DefaultPooledObject<>( connectionFactory.newLdapConnection() );
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
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04101_CANNOT_CREATE_LDAP_CONNECTION_FACTORY, e.getMessage(), e ) );
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
    public void passivateObject( PooledObject<LdapConnection> connection ) throws LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04151_PASSIVATING, connection ) );
        }
    }
  
    
    /**
     * Sets the validator to use when validation occurs.  Note that validation
     * will only occur if the connection pool was configured to validate.  This
     * means one of:
     * <ul>
     * <li>{@link org.apache.commons.pool2.impl.GenericObjectPool#setTestOnBorrow setTestOnBorrow}</li>
     * <li>{@link org.apache.commons.pool2.impl.GenericObjectPool#setTestWhileIdle setTestWhileIdle}</li>
     * <li>{@link org.apache.commons.pool2.impl.GenericObjectPool#setTestOnReturn setTestOnReturn}</li>
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
    public boolean validateObject( PooledObject<LdapConnection> connection )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04152_VALIDATING, connection ) );
        }
        
        return validator.validate( connection.getObject() );
    }
}
