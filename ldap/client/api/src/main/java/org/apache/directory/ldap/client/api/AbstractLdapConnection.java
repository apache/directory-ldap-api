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


import static org.apache.directory.api.ldap.model.message.ResultCodeEnum.processResponse;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;
import org.apache.mina.core.service.IoHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An abstract LdapConnection class gathering the common behavior of LdapConnection
 * concrete classes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractLdapConnection extends IoHandlerAdapter implements LdapConnection
{
    /** logger for reporting errors that might not be handled properly upstream */
    private static final Logger LOG = LoggerFactory.getLogger( AbstractLdapConnection.class );

    /** the schema manager */
    protected SchemaManager schemaManager;

    /** A Message ID which is incremented for each operation */
    protected AtomicInteger messageId;

    /** the ldap codec service */
    protected LdapApiService codec;


    /**
     * Creates a new instance of an AbstractLdapConnection
     */
    protected AbstractLdapConnection()
    {
        this( LdapApiServiceFactory.getSingleton() );
    }

    protected AbstractLdapConnection( LdapApiService codec )
    {
        messageId = new AtomicInteger( 0 );
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( Dn name ) throws LdapException
    {
        byte[] credBytes = Strings.EMPTY_BYTES;

        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setDn( name );
        bindRequest.setCredentials( credBytes );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( String name ) throws LdapException
    {
        LOG.debug( "Bind request : {}", name );

        bind( new Dn( schemaManager, name ), null );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( String name, String credentials ) throws LdapException
    {
        bind( new Dn( schemaManager, name ), credentials );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( Dn name, String credentials ) throws LdapException
    {
        byte[] credBytes = credentials == null ? Strings.EMPTY_BYTES : Strings.getBytesUtf8( credentials );

        BindRequest bindRequest = new BindRequestImpl();
        bindRequest.setDn( name );
        bindRequest.setCredentials( credBytes );

        BindResponse bindResponse = bind( bindRequest );

        processResponse( bindResponse );
    }


    /**
     * Create a complete BindRequest ready to be sent.
     *
     * @param name The DN to bind with
     * @param credentials The user's password
     * @param saslMechanism The SASL mechanism to use
     * @param controls The controls to send
     * @return The created BindRequest
     * @throws LdapException If the creation failed
     */
    protected BindRequest createBindRequest( String name, byte[] credentials, String saslMechanism, Control... controls )
        throws LdapException
    {
        // Set the new messageId
        BindRequest bindRequest = new BindRequestImpl();

        // Set the version
        bindRequest.setVersion3( true );

        // Set the name
        bindRequest.setName( name );

        // Set the credentials
        if ( Strings.isEmpty( saslMechanism ) )
        {
            // Simple bind
            bindRequest.setSimple( true );
            bindRequest.setCredentials( credentials );
        }
        else
        {
            // SASL bind
            bindRequest.setSimple( false );
            bindRequest.setCredentials( credentials );
            bindRequest.setSaslMechanism( saslMechanism );
        }

        // Add the controls
        if ( ( controls != null ) && ( controls.length != 0 ) )
        {
            bindRequest.addAllControls( controls );
        }

        return bindRequest;
    }
}
