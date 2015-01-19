package org.apache.directory.ldap.client.api;

import java.util.LinkedList;
import java.util.Queue;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.DefaultLdapConnectionFactory;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;

public class MockLdapConnectionFactory extends DefaultLdapConnectionFactory 
{
    Queue<LdapConnection> connections = new LinkedList<LdapConnection>();
    
    public MockLdapConnectionFactory( LdapConnectionConfig config ) {
        super( config );
    }
    
    public MockLdapConnectionFactory addConnection( LdapConnection connection ) {
        this.connections.add( connection );
        return this;
    }

    @Override
    public LdapConnection newLdapConnection() throws LdapException
    {
        return bindConnection( this.connections.remove() );
    }

    @Override
    public LdapConnection newUnboundLdapConnection()
    {
        return this.connections.remove();
    }
}