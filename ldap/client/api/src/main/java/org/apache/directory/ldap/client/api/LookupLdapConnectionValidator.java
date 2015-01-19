
package org.apache.directory.ldap.client.api;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;

/**
 * An implementation of {@link LdapConnectionValidator} that attempts a simple
 * lookup on the rootDSE.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
final public class LookupLdapConnectionValidator implements LdapConnectionValidator
{
    /**
     * Returns true if <code>connection</code> is connected, authenticated, and
     * a lookup on the rootDSE returns a non-null response.
     * 
     * @param connection The connection to validate
     * @return True, if the connection is still valid
     */
    public boolean validate( LdapConnection connection )
    {
        try
        {
            return connection.isConnected() 
                && connection.isAuthenticated()
                && ( connection.lookup( Dn.ROOT_DSE, SchemaConstants.NO_ATTRIBUTE ) != null );
        }
        catch ( LdapException e )
        {
            return false;
        }
    }
}