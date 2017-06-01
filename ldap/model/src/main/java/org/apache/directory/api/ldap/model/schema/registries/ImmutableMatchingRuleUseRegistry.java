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
import org.apache.directory.api.ldap.model.schema.MatchingRuleUse;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An immutable wrapper of the MatchingRuleUse registry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableMatchingRuleUseRegistry implements MatchingRuleUseRegistry
{
    /** The wrapped MatchingRuleUse registry */
    MatchingRuleUseRegistry immutableMatchingRuleUseRegistry;


    /**
     * Creates a new instance of ImmutableMatchingRuleUseRegistry.
     *
     * @param matchingRuleUseRegistry The wrapped MatchingRuleUse registry
     */
    public ImmutableMatchingRuleUseRegistry( MatchingRuleUseRegistry matchingRuleUseRegistry )
    {
        immutableMatchingRuleUseRegistry = matchingRuleUseRegistry;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ImmutableMatchingRuleUseRegistry copy()
    {
        return ( ImmutableMatchingRuleUseRegistry ) immutableMatchingRuleUseRegistry.copy();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return immutableMatchingRuleUseRegistry.size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        return immutableMatchingRuleUseRegistry.contains( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        return immutableMatchingRuleUseRegistry.getOidByName( name );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        return immutableMatchingRuleUseRegistry.getSchemaName( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return immutableMatchingRuleUseRegistry.getType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<MatchingRuleUse> iterator()
    {
        return immutableMatchingRuleUseRegistry.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleUse lookup( String oid ) throws LdapException
    {
        return immutableMatchingRuleUseRegistry.lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return immutableMatchingRuleUseRegistry.oidsIterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( MatchingRuleUse schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleUse unregister( String numericOid ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleUse get( String oid )
    {
        return immutableMatchingRuleUseRegistry.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleUse unregister( MatchingRuleUse schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04281 ) );
    }
}
