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
package org.apache.directory.api.ldap.model.schema.registries;


import java.util.Iterator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An immutable wrapper of the Comparator registry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableComparatorRegistry implements ComparatorRegistry
{
    /** The wrapped LdapComparator registry */
    ComparatorRegistry immutableComparatorRegistry;


    /**
     * Creates a new immutable ComparatorRegistry instance.
     * 
     * @param comparatorRegistry The wrapped LdapComparator registry 
     */
    public ImmutableComparatorRegistry( ComparatorRegistry comparatorRegistry )
    {
        immutableComparatorRegistry = comparatorRegistry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( LdapComparator<?> comparator ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> unregister( String numericOid ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ImmutableComparatorRegistry copy()
    {
        return ( ImmutableComparatorRegistry ) immutableComparatorRegistry.copy();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return immutableComparatorRegistry.size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        return immutableComparatorRegistry.contains( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        return immutableComparatorRegistry.getOidByName( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        return immutableComparatorRegistry.getSchemaName( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return immutableComparatorRegistry.getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<LdapComparator<?>> iterator()
    {
        return immutableComparatorRegistry.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> lookup( String oid ) throws LdapException
    {
        return immutableComparatorRegistry.lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return immutableComparatorRegistry.oidsIterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> get( String oid )
    {
        return immutableComparatorRegistry.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> unregister( LdapComparator<?> schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04276 ) );
    }
}
