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




/**
 * A factory for creating LdapConnection objects managed by LdapConnectionPool. The connections are
 * not validated when they are pulled from the pool : we just check if they are still connected, using
 * their internal flag. We don't either re-bind when we push back the connection into the pool.
 * <br>
 * It's up to the users to be careful with the way they deal with connections -especially when using
 * the StartTLS extended operation -.
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
        this.connectionFactory = connectionFactory;
    }
}
