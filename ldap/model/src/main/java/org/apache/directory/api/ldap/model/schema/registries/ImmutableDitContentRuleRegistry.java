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
import org.apache.directory.api.ldap.model.schema.DitContentRule;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An immutable wrapper of the DitContentRule registry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableDitContentRuleRegistry implements DitContentRuleRegistry
{
    /** The wrapped DitContentRule registry */
    DitContentRuleRegistry immutableDITContentRuleRegistry;


    /**
     * Creates a new instance of ImmutableDitContentRuleRegistry.
     *
     * @param ditContentRuleRegistry The wrapped DitContentRule registry
     */
    public ImmutableDitContentRuleRegistry( DitContentRuleRegistry ditContentRuleRegistry )
    {
        immutableDITContentRuleRegistry = ditContentRuleRegistry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ImmutableDitContentRuleRegistry copy()
    {
        return ( ImmutableDitContentRuleRegistry ) immutableDITContentRuleRegistry.copy();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return immutableDITContentRuleRegistry.size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        return immutableDITContentRuleRegistry.contains( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        return immutableDITContentRuleRegistry.getOidByName( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        return immutableDITContentRuleRegistry.getSchemaName( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return immutableDITContentRuleRegistry.getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<DitContentRule> iterator()
    {
        return immutableDITContentRuleRegistry.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitContentRule lookup( String oid ) throws LdapException
    {
        return immutableDITContentRuleRegistry.lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return immutableDITContentRuleRegistry.oidsIterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( DitContentRule schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitContentRule unregister( String numericOid ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitContentRule get( String oid )
    {
        return immutableDITContentRuleRegistry.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitContentRule unregister( DitContentRule schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04277 ) );
    }
}
