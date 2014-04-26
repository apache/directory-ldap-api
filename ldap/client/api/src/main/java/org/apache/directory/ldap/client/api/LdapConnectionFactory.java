package org.apache.directory.ldap.client.api;


import org.apache.directory.api.ldap.model.exception.LdapException;


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
    public abstract LdapConnection bindConnection( LdapConnection connection ) throws LdapException;


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
    public abstract LdapConnection configureConnection( LdapConnection connection );


    /**
     * Returns a newly created, configured, and authenticated connection. This
     * method should be used by a connection pool to manufacture the pooled
     * instances.
     * 
     * @return A newly created, configured, and authenticated LdapConnection.
     * @throws LdapException
     */
    public abstract LdapConnection newLdapConnection() throws LdapException;
    
    
    /**
     * Returns a newly created connection, that has not been bound (bind) that
     * otherwise respects LdapConnectionConfig supplied to the constructor. This
     * is useful for authentication purposes where the consumer will use a bind
     * operation.
     * 
     * @return A newly created and configured LdapConnection.
     */
    public abstract LdapConnection newUnboundLdapConnection();
}
