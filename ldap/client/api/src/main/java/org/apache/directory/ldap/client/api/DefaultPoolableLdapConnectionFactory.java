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
import org.apache.directory.api.ldap.model.exception.LdapException;

/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool. The connections are
 * not validated when they are pulled from the pool : we just check if they are still connected, using
 * their internal flag. 
 * <br>
 * The connections handed out by this factory are monitored : if a borrower changed the bind identity
 * of a connection (an explicit bind() call, or a StartTLS extended operation) before returning it to
 * the pool, the connection is re-bound with the pool's configured identity (and the TLS layer is
 * cleared) when it is passivated. This guarantees the next borrower never inherits the previous
 * borrower's authorization context. Unlike {@link ValidatingPoolableLdapConnectionFactory}, no
 * network operation is performed on passivation when the connection identity was left untouched,
 * so this factory remains the cheaper choice.
 * <br>
 * Applications that really need the historical unmonitored behavior (no identity restoration at
 * all) must explicitly opt out by subclassing this factory and overriding {@link #makeObject()} and
 * {@link #passivateObject(PooledObject)}; be aware that pooled connections then keep the last
 * borrower's bind identity.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultPoolableLdapConnectionFactory extends AbstractPoolableLdapConnectionFactory
{
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
     * Creates a new instance of PoolableLdapConnectionFactory using an instance
     * of the supplied class as its LdapConnection factory.
     *
     * @param config the configuration for creating LdapConnections
     * @param connectionFactoryClass the class used as a factory for connections
     */
    public DefaultPoolableLdapConnectionFactory( LdapConnectionConfig config,
        Class<? extends LdapConnectionFactory> connectionFactoryClass )
    {
        this( newLdapConnectionFactory( config, connectionFactoryClass ) );
    }


    /**
     * Creates a new instance of PoolableLdapConnectionFactory.
     *
     * @param connectionFactory the connection factory for creating LdapConnections
     */
    public DefaultPoolableLdapConnectionFactory( LdapConnectionFactory connectionFactory )
    {
        super( connectionFactory );
    }


    /**
     * {@inheritDoc}
     *
     * Additionally resets the bind/StartTLS monitors of the connection handed
     * out to the borrower.
     */
    @Override
    public void activateObject( PooledObject<LdapConnection> pooledObject ) throws LdapException
    {
        super.activateObject( pooledObject );

        LdapConnection connection = pooledObject.getObject();

        if ( connection instanceof MonitoringLdapConnection )
        {
            // clear the monitors : the borrower starts with the pool's identity
            ( ( MonitoringLdapConnection ) connection ).resetMonitors();
        }
    }


    /**
     * {@inheritDoc}
     *
     * The created connection is wrapped in a {@link MonitoringLdapConnection} so that
     * bind identity changes made by a borrower can be detected and undone when the
     * connection is returned to the pool.
     *
     * @throws LdapException If unable to connect.
     */
    @Override
    public PooledObject<LdapConnection> makeObject() throws LdapException
    {
        return new DefaultPooledObject<LdapConnection>(
            new MonitoringLdapConnection( connectionFactory.newLdapConnection() ) );
    }


    /**
     * {@inheritDoc}
     *
     * If the borrower re-bound the connection (or issued a StartTLS extended operation),
     * the pool's configured identity is restored before the connection is put back into
     * the pool. Nothing is done when the connection identity was left untouched, so no
     * extra network round-trip is paid in the common case.
     *
     * @throws LdapException If unable to reconfigure and rebind.
     */
    @Override
    public void passivateObject( PooledObject<LdapConnection> pooledObject ) throws LdapException
    {
        super.passivateObject( pooledObject );

        LdapConnection connection = pooledObject.getObject();

        if ( connection instanceof MonitoringLdapConnection )
        {
            MonitoringLdapConnection monitor = ( MonitoringLdapConnection ) connection;

            if ( monitor.bindCalled() )
            {
                // The borrower changed the bind identity : restore the pool's identity
                connectionFactory.bindConnection( connection );
            }

            if ( monitor.startTlsCalled() )
            {
                // unbind to clear the TLS layer, then restore the pool's identity
                connection.unBind();
                connectionFactory.bindConnection( connection );
            }
        }
    }
}
