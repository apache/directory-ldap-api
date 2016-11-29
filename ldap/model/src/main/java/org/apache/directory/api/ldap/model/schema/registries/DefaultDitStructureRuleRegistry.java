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


import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.DitStructureRule;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A DitStructureRule registry's service default implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultDitStructureRuleRegistry extends DefaultSchemaObjectRegistry<DitStructureRule>
    implements DitStructureRuleRegistry
{
    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultDitStructureRuleRegistry.class );

    /** A speedup for debug */
    private static final boolean DEBUG = LOG.isDebugEnabled();

    /** a map of DitStructureRule looked up by RuleId */
    protected Map<Integer, DitStructureRule> byRuleId;


    /**
     * Creates a new default NormalizerRegistry instance.
     */
    public DefaultDitStructureRuleRegistry()
    {
        super( SchemaObjectType.DIT_STRUCTURE_RULE, new OidRegistry<DitStructureRule>() );
        byRuleId = new HashMap<>();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( int ruleId )
    {
        return byRuleId.containsKey( ruleId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<DitStructureRule> iterator()
    {
        return byRuleId.values().iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<Integer> ruleIdIterator()
    {
        return byRuleId.keySet().iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( int ruleId ) throws LdapException
    {
        DitStructureRule ditStructureRule = byRuleId.get( ruleId );

        if ( ditStructureRule != null )
        {
            return ditStructureRule.getSchemaName();
        }

        String msg = I18n.err( I18n.ERR_04263, ruleId );
        LOG.warn( msg );
        throw new LdapException( msg );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( DitStructureRule ditStructureRule ) throws LdapException
    {
        int ruleId = ditStructureRule.getRuleId();

        if ( byRuleId.containsKey( ruleId ) )
        {
            String msg = I18n.err( I18n.ERR_04264, ruleId );
            LOG.warn( msg );
            throw new LdapException( msg );
        }

        byRuleId.put( ruleId, ditStructureRule );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( "registered {} for OID {}", ditStructureRule, ruleId );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitStructureRule lookup( int ruleId ) throws LdapException
    {
        DitStructureRule ditStructureRule = byRuleId.get( ruleId );

        if ( ditStructureRule == null )
        {
            String msg = I18n.err( I18n.ERR_04265, ruleId );
            LOG.debug( msg );
            throw new LdapException( msg );
        }

        if ( DEBUG )
        {
            LOG.debug( "Found {} with ruleId: {}", ditStructureRule, ruleId );
        }

        return ditStructureRule;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregister( int ruleId ) throws LdapException
    {
        DitStructureRule ditStructureRule = byRuleId.remove( ruleId );

        if ( DEBUG )
        {
            LOG.debug( "Removed {} with ruleId {} from the registry", ditStructureRule, ruleId );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName )
    {
        if ( schemaName == null )
        {
            return;
        }

        // Loop on all the SchemaObjects stored and remove those associated
        // with the give schemaName
        for ( DitStructureRule ditStructureRule : this )
        {
            if ( schemaName.equalsIgnoreCase( ditStructureRule.getSchemaName() ) )
            {
                int ruleId = ditStructureRule.getRuleId();
                SchemaObject removed = byRuleId.remove( ruleId );

                if ( DEBUG )
                {
                    LOG.debug( "Removed {} with ruleId {} from the registry", removed, ruleId );
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName )
    {
        // Loop on all the SchemaObjects stored and remove those associated
        // with the give schemaName
        for ( DitStructureRule ditStructureRule : this )
        {
            if ( originalSchemaName.equalsIgnoreCase( ditStructureRule.getSchemaName() ) )
            {
                ditStructureRule.setSchemaName( newSchemaName );

                if ( DEBUG )
                {
                    LOG.debug( "Renamed {} schemaName to {}", ditStructureRule, newSchemaName );
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DefaultDitStructureRuleRegistry copy()
    {
        DefaultDitStructureRuleRegistry copy = new DefaultDitStructureRuleRegistry();

        // Copy the base data
        copy.copy( this );

        return copy;
    }
}
