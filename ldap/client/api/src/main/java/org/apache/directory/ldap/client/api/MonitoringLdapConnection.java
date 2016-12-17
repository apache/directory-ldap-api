/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
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


/**
 * A class used to monitor the use of a LdapConnection
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class MonitoringLdapConnection extends LdapConnectionWrapper
{
    private static final Oid START_TLS_OID;

    static
    {
        try
        {
            START_TLS_OID = Oid.fromString( StartTlsRequest.EXTENSION_OID );
        }
        catch ( DecoderException de )
        {
            throw new IllegalStateException( "StartTlsRequest.EXTENSION_OID is not a valid oid... This cant happen", de );
        }
    }

    private boolean bindCalled = false;
    private boolean startTlsCalled = false;


    MonitoringLdapConnection( LdapConnection connection )
    {
        super( connection );
    }


    /**
     * @return tells if a Bind has been issued 
     */
    public boolean bindCalled()
    {
        return bindCalled;
    }


    /**
     * Reset the Bind and StartTLS flags
     */
    public void resetMonitors()
    {
        bindCalled = false;
        startTlsCalled = false;
    }


    /**
     * @return tells if the StarTLS extended operation has been called
     */
    public boolean startTlsCalled()
    {
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
        if ( StartTlsRequest.EXTENSION_OID.equals( oid ) )
        {
            startTlsCalled = true;
        }
        return connection.extended( oid );
    }


    @Override
    public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
    {
        if ( StartTlsRequest.EXTENSION_OID.equals( oid ) )
        {
            startTlsCalled = true;
        }
        return connection.extended( oid, value );
    }


    @Override
    public ExtendedResponse extended( Oid oid ) throws LdapException
    {
        if ( START_TLS_OID.equals( oid ) )
        {
            startTlsCalled = true;
        }
        return connection.extended( oid );
    }


    @Override
    public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
    {
        if ( START_TLS_OID.equals( oid ) )
        {
            startTlsCalled = true;
        }
        return connection.extended( oid, value );
    }


    @Override
    public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
    {
        if ( extendedRequest.hasControl( StartTlsRequest.EXTENSION_OID ) )
        {
            startTlsCalled = true;
        }
        return connection.extended( extendedRequest );
    }
}