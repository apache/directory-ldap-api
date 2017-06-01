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
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An immutable wrapper of the MatchingRule registry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableMatchingRuleRegistry implements MatchingRuleRegistry
{
    /** The wrapped MatchingRule registry */
    MatchingRuleRegistry immutableMatchingRuleRegistry;


    /**
     * Creates a new instance of ImmutableMatchingRuleRegistry.
     *
     * @param matchingRuleRegistry The wrapped MatchingRule registry
     */
    public ImmutableMatchingRuleRegistry( MatchingRuleRegistry matchingRuleRegistry )
    {
        immutableMatchingRuleRegistry = matchingRuleRegistry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ImmutableMatchingRuleRegistry copy()
    {
        return ( ImmutableMatchingRuleRegistry ) immutableMatchingRuleRegistry.copy();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return immutableMatchingRuleRegistry.size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        return immutableMatchingRuleRegistry.contains( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        return immutableMatchingRuleRegistry.getOidByName( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        return immutableMatchingRuleRegistry.getSchemaName( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return immutableMatchingRuleRegistry.getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<MatchingRule> iterator()
    {
        return immutableMatchingRuleRegistry.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRule lookup( String oid ) throws LdapException
    {
        return immutableMatchingRuleRegistry.lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return immutableMatchingRuleRegistry.oidsIterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( MatchingRule schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRule unregister( String numericOid ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRule get( String oid )
    {
        return immutableMatchingRuleRegistry.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRule unregister( MatchingRule schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04280 ) );
    }
}
