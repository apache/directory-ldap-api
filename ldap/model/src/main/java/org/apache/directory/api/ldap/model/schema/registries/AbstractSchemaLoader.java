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


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;


/**
 * An abstract class with a utility method and setListener() implemented.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractSchemaLoader implements SchemaLoader
{
    /**
     * A map of all available schema names to schema objects. This map is
     * populated when this class is created with all the schemas present in
     * the LDIF based schema repository.
     */
    protected final Map<String, Schema> schemaMap = new LowerCaseKeyMap();
    
    /** The flag that tells about the SchemaLoader mode : relaxed or strict */
    private boolean relaxed;

    /**
     * {@inheritDoc}
     */
    @Override
    public final Collection<Schema> getAllEnabled()
    {
        Collection<Schema> enabledSchemas = new ArrayList<>();

        for ( Schema schema : schemaMap.values() )
        {
            if ( schema.isEnabled() )
            {
                enabledSchemas.add( schema );
            }
        }

        return enabledSchemas;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public final Collection<Schema> getAllSchemas()
    {
        return schemaMap.values();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Schema getSchema( String schemaName )
    {
        return schemaMap.get( Strings.toLowerCaseAscii( schemaName ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addSchema( Schema schema )
    {
        schemaMap.put( schema.getSchemaName(), schema );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void removeSchema( Schema schema )
    {
        schemaMap.remove( Strings.toLowerCaseAscii( schema.getSchemaName() ) );
    }


    /**
     * Gets the schema.
     *
     * @param entry the entry
     * @return the schema
     * @throws LdapException the exception
     */
    protected Schema getSchema( Entry entry ) throws LdapException
    {
        if ( entry == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04261 ) );
        }

        Attribute objectClasses = entry.get( SchemaConstants.OBJECT_CLASS_AT );
        boolean isSchema = false;

        for ( Value<?> value : objectClasses )
        {
            if ( MetaSchemaConstants.META_SCHEMA_OC.equalsIgnoreCase( value.getString() ) )
            {
                isSchema = true;
                break;
            }
        }

        if ( !isSchema )
        {
            return null;
        }

        String name;
        String owner;
        String[] dependencies = StringConstants.EMPTY_STRINGS;
        boolean isDisabled = false;

        if ( entry.get( SchemaConstants.CN_AT ) == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04262 ) );
        }

        name = entry.get( SchemaConstants.CN_AT ).getString();

        Attribute creatorsName = entry.get( SchemaConstants.CREATORS_NAME_AT );

        if ( creatorsName == null )
        {
            owner = null;
        }
        else
        {
            owner = creatorsName.getString();
        }

        if ( entry.get( MetaSchemaConstants.M_DISABLED_AT ) != null )
        {
            String value = entry.get( MetaSchemaConstants.M_DISABLED_AT ).getString();
            value = Strings.upperCase( value );
            isDisabled = "TRUE".equals( value );
        }

        if ( entry.get( MetaSchemaConstants.M_DEPENDENCIES_AT ) != null )
        {
            Set<String> depsSet = new HashSet<>();
            Attribute depsAttr = entry.get( MetaSchemaConstants.M_DEPENDENCIES_AT );

            for ( Value<?> value : depsAttr )
            {
                depsSet.add( value.getString() );
            }

            dependencies = depsSet.toArray( StringConstants.EMPTY_STRINGS );
        }

        return new DefaultSchema( this, name, owner, dependencies, isDisabled );
    }


    private Schema[] buildSchemaArray( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = new Schema[schemaNames.length];
        int pos = 0;

        for ( String schemaName : schemaNames )
        {
            schemas[pos++] = getSchema( schemaName );
        }

        return schemas;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadAttributeTypes( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadAttributeTypes( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadComparators( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadComparators( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadDitContentRules( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadDitContentRules( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadDitStructureRules( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadDitStructureRules( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadMatchingRules( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadMatchingRules( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadMatchingRuleUses( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadMatchingRuleUses( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadNameForms( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadNameForms( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadNormalizers( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadNormalizers( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadObjectClasses( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadObjectClasses( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadSyntaxes( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadSyntaxes( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadSyntaxCheckers( String... schemaNames ) throws LdapException, IOException
    {
        if ( schemaNames == null )
        {
            return new ArrayList<>();
        }

        return loadSyntaxCheckers( buildSchemaArray( schemaNames ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRelaxed()
    {
        return relaxed == SchemaManager.RELAXED;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isStrict()
    {
        return relaxed == SchemaManager.STRICT;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRelaxed( boolean relaxed )
    {
        this.relaxed = relaxed;
    }
}
