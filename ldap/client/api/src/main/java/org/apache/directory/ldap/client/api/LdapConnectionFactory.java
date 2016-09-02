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


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * A factory that creates {@link LdapConnection} objects using the provided
 * {@link LdapConnectionConfig}.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapConnectionFactory
{
    /**
     * Issues a bind request on the supplied connection using the name and
     * credentials from the LdapConnectionConfg supplied to the constructor.
     * Returns the connection supplied for chaining.
     * 
     * @param connection
     *            The connection to bind with the configuration credentials.
     * @return The connection supplied.
     * @throws LdapException
     *             If the bind fails.
     */
    LdapConnection bindConnection( LdapConnection connection ) throws LdapException;


    /**
     * Applies the following configuration settings from the
     * LdapConnectionConfig to the supplied connection:
     * <ul>
     * <li>timeOut</li>
     * <li>binaryAttributeDetector</li>
     * </ul>
     * This method is called by newLdapConnection, so there is no need to call
     * this on a newly created connection. This should be used for pooling where
     * the returned connection could have been modified by the borrower in order
     * to ensure the next borrower gets a correctly configured connection.
     * Returns the supplied connection for chaining.
     * 
     * @param connection
     *            The connection to configure
     * @return The supplied connection.
     */
    LdapConnection configureConnection( LdapConnection connection );


    /**
     * Returns the LdapApiService instance used by this factory.
     *
     * @return The LdapApiService instance used by this factory
     */
    LdapApiService getLdapApiService();


    /**
     * Returns a newly created, configured, and authenticated connection. This
     * method should be used by a connection pool to manufacture the pooled
     * instances.
     * 
     * @return A newly created, configured, and authenticated LdapConnection.
     * @throws LdapException If the new connection couldn't be established
     */
    LdapConnection newLdapConnection() throws LdapException;


    /**
     * Returns a newly created connection, that has not been bound (bind) that
     * otherwise respects LdapConnectionConfig supplied to the constructor. This
     * is useful for authentication purposes where the consumer will use a bind
     * operation.
     * 
     * @return A newly created and configured LdapConnection.
     */
    LdapConnection newUnboundLdapConnection();
}
