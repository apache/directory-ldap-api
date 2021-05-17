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


import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool. 
 * A bind operation is executed upon return if any of the following operations 
 * were performed on the connection while it was checked out:
 * 
 * <ul>
 * <li>{@link LdapConnection#bind() bind()}</li>
 * <li>{@link LdapConnection#anonymousBind() anonymousBind()}</li>
 * <li>{@link LdapConnection#bind(String) bind(String)}</li>
 * <li>{@link LdapConnection#bind(String, String) bind(String, String)}</li>
 * <li>{@link LdapConnection#bind(Dn) bind(Dn)}</li>
 * <li>{@link LdapConnection#bind(Dn, String) bind(Dn, String)}</li>
 * <li>{@link LdapConnection#bind(BindRequest) bind(BindRequest)}</li>
 * <li>{@link LdapConnection#extended(String) extended(String)} <i>where oid is StartTLS</i></li>
 * <li>{@link LdapConnection#extended(String, byte[]) extended(String, byte[])} <i>where oid is StartTLS</i></li>
 * <li>{@link LdapConnection#extended(Oid) extended(String)} <i>where oid is StartTLS</i></li>
 * <li>{@link LdapConnection#extended(Oid, byte[]) extended(String, byte[])} <i>where oid is StartTLS</i></li>
 * <li>{@link LdapConnection#extended(ExtendedRequest) extended(ExtendedRequest)} <i>where ExtendedRequest is StartTLS</i></li>
 * </ul>
 * 
 * This is a <i>MOSTLY</i> safe way to handle connections in a pool. If one 
 * would like to use a slightly less expensive pool factory, the 
 * {@link DefaultPoolableLdapConnectionFactory} may be the right choice.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ValidatingPoolableLdapConnectionFactory extends AbstractPoolableLdapConnectionFactory
{
    /** This class logger */
    private static final Logger LOG = LoggerFactory.getLogger( ValidatingPoolableLdapConnectionFactory.class );


    /**
     * Creates a new instance of ValidatingPoolableLdapConnectionFactory.
     *
     * @param config the configuration for creating LdapConnections
     */
    public ValidatingPoolableLdapConnectionFactory( LdapConnectionConfig config )
    {
        this( new DefaultLdapConnectionFactory( config ) );
    }


    /**
     * Creates a new instance of ValidatingPoolableLdapConnectionFactory.  The
     * <code>connectionFactoryClass</code> must have a public constructor accepting
     * an <code>LdapConnectionConfig</code> object or an 
     * <code>IllegalArgumentException</code> will be thrown.
     *
     * @param config the configuration for creating LdapConnections
     * @param connectionFactoryClass An implementation class of for the 
     * LDAP connection factory.
     * @throws IllegalArgumentException If the instantiation of an instance of 
     * the <code>connectionFactoryClass</code> fails.
     */
    public ValidatingPoolableLdapConnectionFactory( LdapConnectionConfig config,
        Class<? extends LdapConnectionFactory> connectionFactoryClass )
    {
        this( newLdapConnectionFactory( config, connectionFactoryClass ) );
    }


    /**
     * Creates a new instance of ValidatingPoolableLdapConnectionFactory.
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
    @Override
    public void activateObject( PooledObject<LdapConnection> pooledObject ) throws LdapException
    {
        LdapConnection connection = pooledObject.getObject();
        
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04146_ACTIVATING, connection ) );
        }
        
        super.activateObject( pooledObject );

        // clear the monitors
        ( ( MonitoringLdapConnection ) connection ).resetMonitors();
    }


    /**
     * {@inheritDoc}
     * 
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
        
        return new DefaultPooledObject<LdapConnection>( new MonitoringLdapConnection( connectionFactory.newLdapConnection() ) );
    }


    /**
     * {@inheritDoc}
     * 
     * Here, passivating a connection means we re-bind it, so that the existing LDAPSession
     * is reset.
     * 
     * @throws LdapException If unable to reconfigure and rebind.
     */
    @Override
    public void passivateObject( PooledObject<LdapConnection> pooledObject ) throws LdapException
    {
        LdapConnection connection = pooledObject.getObject();

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04151_PASSIVATING, connection ) );
        }

        if ( !connection.isConnected() || !connection.isAuthenticated()
            || ( ( MonitoringLdapConnection ) connection ).bindCalled() )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04172_REBIND_BIND_CONNECTION, connection ) );
            }
            
            connectionFactory.bindConnection( connection );
        }
        
        if ( ( ( MonitoringLdapConnection ) connection ).startTlsCalled() )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04173_UNBIND_START_TLS, connection ) );
            }
            
            // unbind to clear the tls
            connection.unBind();
            connectionFactory.bindConnection( connection );
        }

        // in case connection had configuration changed
        connectionFactory.configureConnection( connection );
    }
}
