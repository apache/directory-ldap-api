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
package org.apache.directory.ldap.client.template;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyDecorator;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.EntryCursorImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.exception.LdapRequestUnsuccessfulException;
import org.apache.directory.ldap.client.template.exception.LdapRuntimeException;
import org.apache.directory.ldap.client.template.exception.PasswordException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A facade for LDAP operations that handles all of the boiler plate code for 
 * you allowing more concise operations through the use of callbacks.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * 
 * @see <a href="http://en.wikipedia.org/wiki/Template_method_pattern">Template method pattern</a>
 */
public class LdapConnectionTemplate implements LdapConnectionOperations, ModelFactory
{
    private static final Logger LOG = LoggerFactory.getLogger( LdapConnectionTemplate.class );
    private static final EntryMapper<Dn> DN_ENTRY_MAPPER = new EntryMapper<Dn>()
    {
        @Override
        public Dn map( Entry entry ) throws LdapException
        {
            return entry.getDn();
        }
    };

    private LdapConnectionPool connectionPool;
    private final PasswordPolicyDecorator passwordPolicyRequestControl;
    private PasswordPolicyResponder passwordPolicyResponder;
    private ModelFactory modelFactory;


    /**
     * Creates a new instance of LdapConnectionTemplate.
     *
     * @param connectionPool The pool to obtain connections from.
     */
    public LdapConnectionTemplate( LdapConnectionPool connectionPool )
    {
        LOG.debug( "creating new connection template from connectionPool" );
        this.connectionPool = connectionPool;
        this.passwordPolicyRequestControl = new PasswordPolicyDecorator(
            connectionPool.getLdapApiService() );
        this.passwordPolicyResponder = new PasswordPolicyResponderImpl(
            connectionPool.getLdapApiService() );
        this.modelFactory = new ModelFactoryImpl();
    }


    @Override
    public AddResponse add( Dn dn, final Attribute... attributes )
    {
        return add( dn,
            new RequestBuilder<AddRequest>()
            {
                @Override
                public void buildRequest( AddRequest request ) throws LdapException
                {
                    request.getEntry().add( attributes );
                }
            } );
    }


    @Override
    public AddResponse add( Dn dn, RequestBuilder<AddRequest> requestBuilder )
    {
        AddRequest addRequest = newAddRequest( newEntry( dn ) );
        try
        {
            requestBuilder.buildRequest( addRequest );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        return add( addRequest );
    }


    @Override
    public AddResponse add( AddRequest addRequest )
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            return connection.add( addRequest );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    @Override
    public PasswordWarning authenticate( String baseDn, String filter, SearchScope scope, char[] password )
        throws PasswordException
    {
        return authenticate( newSearchRequest( baseDn, filter, scope ), password );
    }


    @Override
    public PasswordWarning authenticate( Dn baseDn, String filter, SearchScope scope, char[] password )
        throws PasswordException
    {
        return authenticate( newSearchRequest( baseDn, filter, scope ), password );
    }


    @Override
    public PasswordWarning authenticate( SearchRequest searchRequest, char[] password ) throws PasswordException
    {
        Dn userDn = searchFirst( searchRequest, DN_ENTRY_MAPPER );
        if ( userDn == null )
        {
            throw new PasswordException().setResultCode( ResultCodeEnum.INVALID_CREDENTIALS );
        }

        return authenticate( userDn, password );
    }


    @Override
    public PasswordWarning authenticate( Dn userDn, char[] password ) throws PasswordException
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            return authenticateConnection( connection, userDn, password );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    private PasswordWarning authenticateConnection( final LdapConnection connection,
        final Dn userDn, final char[] password ) throws PasswordException
    {
        return passwordPolicyResponder.process(
            new PasswordPolicyOperation()
            {
                @Override
                public ResultResponse process() throws LdapException
                {
                    MemoryClearingBuffer passwordBuffer = MemoryClearingBuffer.newInstance( password );
                    try
                    {
                        BindRequest bindRequest = new BindRequestImpl()
                            .setDn( userDn )
                            .setCredentials( passwordBuffer.getBytes() )
                            .addControl( passwordPolicyRequestControl );

                        return connection.bind( bindRequest );
                    }
                    finally
                    {
                        passwordBuffer.clear();
                    }
                }
            } );
    }


    @Override
    public DeleteResponse delete( Dn dn )
    {
        return delete( dn, null );
    }


    @Override
    public DeleteResponse delete( Dn dn, RequestBuilder<DeleteRequest> requestBuilder )
    {
        DeleteRequest deleteRequest = newDeleteRequest( dn );
        if ( requestBuilder != null )
        {
            try
            {
                requestBuilder.buildRequest( deleteRequest );
            }
            catch ( LdapException e )
            {
                throw new LdapRuntimeException( e );
            }
        }
        return delete( deleteRequest );
    }


    @Override
    public DeleteResponse delete( DeleteRequest deleteRequest )
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            return connection.delete( deleteRequest );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    @Override
    public <T> T execute( ConnectionCallback<T> connectionCallback )
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            return connectionCallback.doWithConnection( connection );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    @Override
    public <T> T lookup( Dn dn, EntryMapper<T> entryMapper )
    {
        return lookup( dn, null, entryMapper );
    }


    @Override
    public <T> T lookup( Dn dn, String[] attributes, EntryMapper<T> entryMapper )
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            Entry entry = attributes == null
                ? connection.lookup( dn )
                : connection.lookup( dn, attributes );
            return entry == null ? null : entryMapper.map( entry );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    private void modifyPassword( final LdapConnection connection, final Dn userDn,
        final char[] newPassword ) throws PasswordException
    {
        passwordPolicyResponder.process(
            new PasswordPolicyOperation()
            {
                @Override
                public ResultResponse process() throws PasswordException, LdapException
                {
                    // Can't use Password Modify:
                    // https://issues.apache.org/jira/browse/DIRSERVER-1935
                    // So revert to regular Modify
                    MemoryClearingBuffer newPasswordBuffer = MemoryClearingBuffer.newInstance( newPassword );
                    try
                    {
                        ModifyRequest modifyRequest = new ModifyRequestImpl()
                            .setName( userDn )
                            .replace( "userPassword", newPasswordBuffer.getComputedBytes() )
                            .addControl( passwordPolicyRequestControl );

                        return connection.modify( modifyRequest );
                    }
                    finally
                    {
                        newPasswordBuffer.clear();
                    }
                }
            } );

    }


    @Override
    public void modifyPassword( Dn userDn, char[] newPassword )
        throws PasswordException
    {
        modifyPassword( userDn, null, newPassword, true );
    }


    @Override
    public void modifyPassword( Dn userDn, char[] oldPassword,
        char[] newPassword ) throws PasswordException
    {
        modifyPassword( userDn, oldPassword, newPassword, false );
    }


    @Override
    public void modifyPassword( Dn userDn, char[] oldPassword,
        char[] newPassword, boolean asAdmin ) throws PasswordException
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            if ( !asAdmin )
            {
                authenticateConnection( connection, userDn, oldPassword );
            }

            modifyPassword( connection, userDn, newPassword );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    @Override
    public ModifyResponse modify( Dn dn, RequestBuilder<ModifyRequest> requestBuilder )
    {
        ModifyRequest modifyRequest = newModifyRequest( dn );
        try
        {
            requestBuilder.buildRequest( modifyRequest );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        return modify( modifyRequest );
    }


    @Override
    public ModifyResponse modify( ModifyRequest modifyRequest )
    {
        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();
            return connection.modify( modifyRequest );
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }
    }


    @Override
    public AddRequest newAddRequest( Entry entry )
    {
        return modelFactory.newAddRequest( entry );
    }


    @Override
    public Attribute newAttribute( String name )
    {
        return modelFactory.newAttribute( name );
    }


    @Override
    public Attribute newAttribute( String name, byte[]... values )
    {
        return modelFactory.newAttribute( name, values );
    }


    @Override
    public Attribute newAttribute( String name, String... values )
    {
        return modelFactory.newAttribute( name, values );
    }


    @Override
    public Attribute newAttribute( String name, Value<?>... values )
    {
        return modelFactory.newAttribute( name, values );
    }


    @Override
    public DeleteRequest newDeleteRequest( Dn dn )
    {
        return modelFactory.newDeleteRequest( dn );
    }


    @Override
    public Dn newDn( String dn )
    {
        return modelFactory.newDn( dn );
    }


    @Override
    public Entry newEntry( String dn )
    {
        return modelFactory.newEntry( dn );
    }


    @Override
    public Entry newEntry( Dn dn )
    {
        return modelFactory.newEntry( dn );
    }


    @Override
    public ModifyRequest newModifyRequest( String dn )
    {
        return modelFactory.newModifyRequest( dn );
    }


    @Override
    public ModifyRequest newModifyRequest( Dn dn )
    {
        return modelFactory.newModifyRequest( dn );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter, SearchScope scope )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, String filter, SearchScope scope )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter, SearchScope scope )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, String filter, SearchScope scope )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter, SearchScope scope, String... attributes )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, String filter, SearchScope scope, String... attributes )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter, SearchScope scope, String... attributes )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, String filter, SearchScope scope, String... attributes )
    {
        return modelFactory.newSearchRequest( baseDn, filter, scope, attributes );
    }


    @Override
    public <T extends ResultResponse> T responseOrException( T response )
    {
        if ( ResultCodeEnum.SUCCESS != response.getLdapResult().getResultCode() )
        {
            throw new LdapRequestUnsuccessfulException( response );
        }
        return response;
    }


    private void returnLdapConnection( LdapConnection connection )
    {
        if ( connection != null )
        {
            try
            {
                connectionPool.releaseConnection( connection );
            }
            catch ( LdapException e )
            {
                throw new LdapRuntimeException( e );
            }
        }
    }


    @Override
    public <T> List<T> search( String baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( String baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( Dn baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( Dn baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( String baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( String baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( Dn baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( Dn baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return search(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> List<T> search( SearchRequest searchRequest,
        EntryMapper<T> entryMapper )
    {
        List<T> entries = new ArrayList<>();

        LdapConnection connection = null;
        try
        {
            connection = connectionPool.getConnection();

            for ( Entry entry : new EntryCursorImpl( connection.search( searchRequest ) ) )
            {
                entries.add( entryMapper.map( entry ) );
            }
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        finally
        {
            returnLdapConnection( connection );
        }

        return entries;
    }


    @Override
    public <T> T searchFirst( String baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( String baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( Dn baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( Dn baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( String baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( String baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( Dn baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( Dn baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper )
    {
        return searchFirst(
            modelFactory.newSearchRequest( baseDn, filter, scope, attributes ),
            entryMapper );
    }


    @Override
    public <T> T searchFirst( SearchRequest searchRequest,
        EntryMapper<T> entryMapper )
    {
        // in case the caller did not set size limit, we cache original value,
        // set to 1, then set back to original value before returning...
        long originalSizeLimit = searchRequest.getSizeLimit();
        try
        {
            searchRequest.setSizeLimit( 1 );
            List<T> entries = search( searchRequest, entryMapper );
            return entries.isEmpty() ? null : entries.get( 0 );
        }
        finally
        {
            searchRequest.setSizeLimit( originalSizeLimit );
        }
    }


    /**
     * Sets the <code>modelFactory</code> implementation for this facade.
     *
     * @param modelFactory The model factory implementation
     */
    public void setModelFactory( ModelFactory modelFactory )
    {
        this.modelFactory = modelFactory;
    }


    /**
     * Sets the <code>passwordPolicyResponder</code> implementation for this
     * facade.
     *
     * @param passwordPolicyResponder The password policy responder 
     * implementation
     */
    public void setPasswordPolicyResponder( PasswordPolicyResponder passwordPolicyResponder )
    {
        this.passwordPolicyResponder = passwordPolicyResponder;
    }
}
