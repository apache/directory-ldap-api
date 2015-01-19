
package org.apache.directory.ldap.client.api;


/**
 * An implementation of {@link LdapConnectionValidator} that checks to see that
 * the connection <code>isConnected()</code> and <code>isAuthenticated()</code>.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
final public class DefaultLdapConnectionValidator implements LdapConnectionValidator
{
    /**
     * Returns true if <code>connection</code> is connected, and authenticated.
     * 
     * @param connection The connection to validate
     * @return True, if the connection is still valid
     */
    public boolean validate( LdapConnection connection )
    {
        return connection.isConnected() && connection.isAuthenticated();
    }
}