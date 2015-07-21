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

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.exception.LdapRuntimeException;


/**
 * The default implementation of {@link ModelFactory}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class ModelFactoryImpl implements ModelFactory
{
    @Override
    public AddRequest newAddRequest( Entry entry )
    {
        return new AddRequestImpl().setEntry( entry );
    }


    @Override
    public Attribute newAttribute( String name )
    {
        return new DefaultAttribute( name );
    }


    @Override
    public Attribute newAttribute( String name, byte[]... values )
    {
        return new DefaultAttribute( name, values );
    }

    
    @Override
    public Attribute newAttribute( String name, String... values )
    {
        return new DefaultAttribute( name, values );
    }
    

    @Override
    public Attribute newAttribute( String name, Value<?>... values )
    {
        return new DefaultAttribute( name, values );
    }


    @Override
    public DeleteRequest newDeleteRequest( Dn dn )
    {
        return new DeleteRequestImpl()
            .setName( dn );
    }


    @Override
    public Dn newDn( String dn )
    {
        try
        {
            return new Dn( dn );
        }
        catch ( LdapInvalidDnException e )
        {
            throw new LdapRuntimeException( e );
        }
    }


    @Override
    public Entry newEntry( String dn )
    {
        return newEntry( newDn( dn ) );
    }


    @Override
    public Entry newEntry( Dn dn )
    {
        return new DefaultEntry( dn );
    }


    @Override
    public ModifyRequest newModifyRequest( String dn )
    {
        return newModifyRequest( newDn( dn ) );
    }


    @Override
    public ModifyRequest newModifyRequest( Dn dn )
    {
        return new ModifyRequestImpl().setName( dn );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter,
        SearchScope scope )
    {
        return newSearchRequest( newDn( baseDn ), filter.toString(), scope );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, String filter,
        SearchScope scope )
    {
        return newSearchRequest( newDn( baseDn ), filter, scope );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter,
        SearchScope scope )
    {
        return newSearchRequest( baseDn, filter.toString(), scope, ( String[] ) null );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, String filter,
        SearchScope scope )
    {
        return newSearchRequest( baseDn, filter, scope, ( String[] ) null );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter,
        SearchScope scope, String... attributes )
    {
        return newSearchRequest( newDn( baseDn ), filter.toString(), scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( String baseDn, String filter,
        SearchScope scope, String... attributes )
    {
        return newSearchRequest( newDn( baseDn ), filter, scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter,
        SearchScope scope, String... attributes )
    {
        return newSearchRequest( baseDn, filter.toString(), scope, attributes );
    }


    @Override
    public SearchRequest newSearchRequest( Dn baseDn, String filter,
        SearchScope scope, String... attributes )
    {
        SearchRequest searchRequest = null;
        try
        {
            searchRequest = new SearchRequestImpl()
                .setBase( baseDn )
                .setFilter( filter )
                .setScope( scope == null ? SearchScope.OBJECT : scope );
            if ( attributes != null && attributes.length > 0 )
            {
                searchRequest.addAttributes( attributes );
            }
        }
        catch ( LdapException e )
        {
            throw new LdapRuntimeException( e );
        }
        return searchRequest;
    }
}
