
package org.apache.directory.ldap.client.api;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.name.Dn;

public final class MonitoringLdapConnection extends LdapConnectionWrapper
{
    private static final Oid START_TLS_OID;

    
    static 
    {
       try
        {
            START_TLS_OID = Oid.fromString( StartTlsRequest.EXTENSION_OID );
        }
        catch ( DecoderException e )
        {
            throw new IllegalStateException( "StartTlsRequest.EXTENSION_OID is not a valid oid... This cant happen" );
        }
    }


    private boolean bindCalled = false;
    private boolean startTlsCalled = false;
    
    MonitoringLdapConnection( LdapConnection connection ) 
    {
        super( connection );
    }
    
    public boolean bindCalled() {
        return bindCalled;
    }
    
    public void resetMonitors() {
        bindCalled = false;
        startTlsCalled = false;
    }
    
    public boolean startTlsCalled() {
        return startTlsCalled;
    }

    @Override
    public void bind() throws LdapException
    {
        connection.bind();
        bindCalled = true;
    }

    @Override
    public void anonymousBind() throws LdapException
    {
        connection.anonymousBind();
        bindCalled = true;
    }

    @Override
    public void bind( String name ) throws LdapException
    {
        connection.bind( name );
        bindCalled = true;
    }

    @Override
    public void bind( String name, String credentials ) throws LdapException
    {
        connection.bind( name, credentials );
        bindCalled = true;
    }

    @Override
    public void bind( Dn name ) throws LdapException
    {
        connection.bind( name );
        bindCalled = true;
    }

    @Override
    public void bind( Dn name, String credentials ) throws LdapException
    {
        connection.bind( name, credentials );
        bindCalled = true;
    }

    @Override
    public BindResponse bind( BindRequest bindRequest ) throws LdapException
    {
        BindResponse response = connection.bind( bindRequest );
        bindCalled = true;
        return response;
    }

    @Override
    public ExtendedResponse extended( String oid ) throws LdapException
    {
        if ( StartTlsRequest.EXTENSION_OID.equals( oid ) ) {
            startTlsCalled = true;
        }
        return connection.extended( oid );
    }

    @Override
    public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
    {
        if ( StartTlsRequest.EXTENSION_OID.equals( oid ) ) {
            startTlsCalled = true;
        }
        return connection.extended( oid, value );
    }

    @Override
    public ExtendedResponse extended( Oid oid ) throws LdapException
    {
        if ( START_TLS_OID.equals( oid ) ) {
            startTlsCalled = true;
        }
        return connection.extended( oid );
    }

    @Override
    public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
    {
        if ( START_TLS_OID.equals( oid ) ) {
            startTlsCalled = true;
        }
        return connection.extended( oid, value );
    }

    @Override
    public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest.hasControl( StartTlsRequest.EXTENSION_OID ) ) {
            startTlsCalled = true;
        }
        return connection.extended( extendedRequest );
    }
}