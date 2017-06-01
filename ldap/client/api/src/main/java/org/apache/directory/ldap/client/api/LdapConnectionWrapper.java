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


import java.io.IOException;
import java.util.List;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


/**
 * Provides a base implementation of a {@link Wrapper} for {@link LdapConnection}
 * objects.  All methods are passed through to the wrapped 
 * <code>LdapConnection</code>.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapConnectionWrapper implements LdapConnection, Wrapper<LdapConnection>
{
    /** The wrapped connection */
    protected LdapConnection connection;


    /**
     * Creates a new LdapConnectionWrapper instance
     * 
     * @param connection The wrapped connection
     */
    protected LdapConnectionWrapper( LdapConnection connection )
    {
        this.connection = connection;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapConnection wrapped()
    {
        return connection;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isConnected()
    {
        return connection.isConnected();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAuthenticated()
    {
        return connection.isAuthenticated();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean connect() throws LdapException
    {
        return connection.connect();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        connection.close();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void add( Entry entry ) throws LdapException
    {
        connection.add( entry );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AddResponse add( AddRequest addRequest ) throws LdapException
    {
        return connection.add( addRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon( int messageId )
    {
        connection.abandon( messageId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void abandon( AbandonRequest abandonRequest )
    {
        connection.abandon( abandonRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind() throws LdapException
    {
        connection.bind();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void anonymousBind() throws LdapException
    {
        connection.anonymousBind();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( String name ) throws LdapException
    {
        connection.bind( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( String name, String credentials ) throws LdapException
    {
        connection.bind( name, credentials );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( Dn name ) throws LdapException
    {
        connection.bind( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void bind( Dn name, String credentials ) throws LdapException
    {
        connection.bind( name, credentials );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindResponse bind( BindRequest bindRequest ) throws LdapException
    {
        return connection.bind( bindRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EntryCursor search( Dn baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return connection.search( baseDn, filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException
    {
        return connection.search( baseDn, filter, scope, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SearchCursor search( SearchRequest searchRequest ) throws LdapException
    {
        return connection.search( searchRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unBind() throws LdapException
    {
        connection.unBind();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeOut( long timeOut )
    {
        connection.setTimeOut( timeOut );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Dn dn, Modification... modifications ) throws LdapException
    {
        connection.modify( dn, modifications );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( String dn, Modification... modifications ) throws LdapException
    {
        connection.modify( dn, modifications );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void modify( Entry entry, ModificationOperation modOp ) throws LdapException
    {
        connection.modify( entry, modOp );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyResponse modify( ModifyRequest modRequest ) throws LdapException
    {
        return connection.modify( modRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( String entryDn, String newRdn ) throws LdapException
    {
        connection.rename( entryDn, newRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn entryDn, Rdn newRdn ) throws LdapException
    {
        connection.rename( entryDn, newRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( String entryDn, String newRdn, boolean deleteOldRdn ) throws LdapException
    {
        connection.rename( entryDn, newRdn, deleteOldRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rename( Dn entryDn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException
    {
        connection.rename( entryDn, newRdn, deleteOldRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( String entryDn, String newSuperiorDn ) throws LdapException
    {
        connection.move( entryDn, newSuperiorDn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void move( Dn entryDn, Dn newSuperiorDn ) throws LdapException
    {
        connection.move( entryDn, newSuperiorDn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn entryDn, Dn newDn ) throws LdapException
    {
        connection.moveAndRename( entryDn, newDn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( String entryDn, String newDn ) throws LdapException
    {
        connection.moveAndRename( entryDn, newDn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( Dn entryDn, Dn newDn, boolean deleteOldRdn ) throws LdapException
    {
        connection.moveAndRename( entryDn, newDn, deleteOldRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void moveAndRename( String entryDn, String newDn, boolean deleteOldRdn ) throws LdapException
    {
        connection.moveAndRename( entryDn, newDn, deleteOldRdn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyDnResponse modifyDn( ModifyDnRequest modDnRequest ) throws LdapException
    {
        return connection.modifyDn( modDnRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( String dn ) throws LdapException
    {
        connection.delete( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void delete( Dn dn ) throws LdapException
    {
        connection.delete( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DeleteResponse delete( DeleteRequest deleteRequest ) throws LdapException
    {
        return connection.delete( deleteRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, String value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, byte[] value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( String dn, String attributeName, Value<?> value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, String value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, byte[] value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean compare( Dn dn, String attributeName, Value<?> value ) throws LdapException
    {
        return connection.compare( dn, attributeName, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CompareResponse compare( CompareRequest compareRequest ) throws LdapException
    {
        return connection.compare( compareRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( String oid ) throws LdapException
    {
        return connection.extended( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( String oid, byte[] value ) throws LdapException
    {
        return connection.extended( oid, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( Oid oid ) throws LdapException
    {
        return connection.extended( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException
    {
        return connection.extended( oid, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException
    {
        return connection.extended( extendedRequest );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( String dn ) throws LdapException
    {
        return connection.exists( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean exists( Dn dn ) throws LdapException
    {
        return connection.exists( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getRootDse() throws LdapException
    {
        return connection.getRootDse();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry getRootDse( String... attributes ) throws LdapException
    {
        return connection.getRootDse( attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn ) throws LdapException
    {
        return connection.lookup( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn ) throws LdapException
    {
        return connection.lookup( dn );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, String... attributes ) throws LdapException
    {
        return connection.lookup( dn, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( Dn dn, Control[] controls, String... attributes ) throws LdapException
    {
        return connection.lookup( dn, controls, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn, String... attributes ) throws LdapException
    {
        return connection.lookup( dn, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry lookup( String dn, Control[] controls, String... attributes ) throws LdapException
    {
        return connection.lookup( dn, controls, attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isControlSupported( String controlOID ) throws LdapException
    {
        return connection.isControlSupported( controlOID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getSupportedControls() throws LdapException
    {
        return connection.getSupportedControls();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void loadSchema() throws LdapException
    {
        connection.loadSchema();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaManager getSchemaManager()
    {
        return connection.getSchemaManager();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapApiService getCodecService()
    {
        return connection.getCodecService();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRequestCompleted( int messageId )
    {
        return connection.isRequestCompleted( messageId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean doesFutureExistFor( int messageId )
    {
        return connection.isRequestCompleted( messageId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BinaryAttributeDetector getBinaryAttributeDetector()
    {
        return connection.getBinaryAttributeDetector();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetecter )
    {
        connection.setBinaryAttributeDetector( binaryAttributeDetecter );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        connection.setSchemaManager( schemaManager );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void loadSchemaRelaxed() throws LdapException
    {
        connection.loadSchemaRelaxed();
    }
}