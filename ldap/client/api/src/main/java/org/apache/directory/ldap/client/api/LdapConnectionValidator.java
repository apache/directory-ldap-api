
package org.apache.directory.ldap.client.api;


/**
 * An LdapConnection validator intended to be used by a GenericObjectPool to
 * determine whether or not a conneciton is still <i>usable</i>.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapConnectionValidator
{
    /**
     * Return true if the connection is still valid.  This means that if this
     * connections is handed out to a user, it <i>should</i> allow for 
     * successful communication with the server.
     *
     * @param ldapConnection The connection to test
     * @return True, if the connection is still valid
     */
    public boolean validate( LdapConnection ldapConnection );
}
