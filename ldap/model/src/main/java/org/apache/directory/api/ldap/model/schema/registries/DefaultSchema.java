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


import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.SchemaObjectWrapper;
import org.apache.directory.api.util.StringConstants;


/**
 * The default Schema interface implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultSchema implements Schema
{
    /** The default schema's owner */
    protected static final String DEFAULT_OWNER = "uid=admin,ou=system";

    /** Tells if this schema is disabled */
    protected boolean disabled;

    /** Contains the list of schema it depends on */
    protected String[] dependencies;

    /** The schema owner */
    protected String owner;

    /** The schema name */
    protected String name;

    /** The set of SchemaObjects declared in this schema */
    protected Set<SchemaObjectWrapper> content;
    
    /** The SchemaLoader used to load this schema */
    protected SchemaLoader schemaLoader;


    /**
     * Creates a new instance of DefaultSchema.
     *
     * @param schemaLoader The ShcemaLoader to use
     * @param name The schema's name
     */
    public DefaultSchema( SchemaLoader schemaLoader, String name )
    {
        this( schemaLoader, name, null, null, false );
    }


    /**
     * Creates a new instance of DefaultSchema.
     *
     * @param schemaLoader The ShcemaLoader to use
     * @param name The schema's name
     * @param owner the schema's owner
     */
    public DefaultSchema( SchemaLoader schemaLoader, String name, String owner )
    {
        this( schemaLoader, name, owner, null, false );
    }


    /**
     * Creates a new instance of DefaultSchema.
     *
     * @param schemaLoader The ShcemaLoader to use
     * @param name The schema's name
     * @param owner the schema's owner
     * @param dependencies The list of schemas it depends on 
     */
    public DefaultSchema( SchemaLoader schemaLoader, String name, String owner, String[] dependencies )
    {
        this( schemaLoader, name, owner, dependencies, false );
    }


    /**
     * Creates a new instance of DefaultSchema.
     *
     * @param schemaLoader The ShcemaLoader to use
     * @param name The schema's name
     * @param owner the schema's owner
     * @param dependencies The list of schemas it depends on
     * @param disabled Set the status for this schema 
     */
    public DefaultSchema( SchemaLoader schemaLoader, String name, String owner, String[] dependencies, boolean disabled )
    {
        if ( name == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_04266 ) );
        }

        this.name = name;

        if ( owner != null )
        {
            this.owner = owner;
        }
        else
        {
            this.owner = DEFAULT_OWNER;
        }

        if ( dependencies != null )
        {
            this.dependencies = new String[dependencies.length];
            System.arraycopy( dependencies, 0, this.dependencies, 0, dependencies.length );
        }
        else
        {
            this.dependencies = StringConstants.EMPTY_STRINGS;
        }

        this.disabled = disabled;

        content = new HashSet<>();
        
        this.schemaLoader = schemaLoader;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getDependencies()
    {
        String[] copy = new String[dependencies.length];
        System.arraycopy( dependencies, 0, copy, 0, dependencies.length );
        return copy;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addDependencies( String... dependenciesToAdd )
    {
        if ( dependenciesToAdd != null )
        {
            int start = 0;

            if ( dependencies == null )
            {
                dependencies = new String[dependenciesToAdd.length];
            }
            else
            {
                String[] tempDependencies = new String[dependencies.length + dependenciesToAdd.length];
                System.arraycopy( dependencies, 0, tempDependencies, 0, dependencies.length );
                start = dependencies.length;
                dependencies = tempDependencies;
            }

            System.arraycopy( dependenciesToAdd, 0, dependencies, start, dependenciesToAdd.length );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOwner()
    {
        return owner;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName()
    {
        return name;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDisabled()
    {
        return disabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEnabled()
    {
        return !disabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void disable()
    {
        this.disabled = true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void enable()
    {
        this.disabled = false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<SchemaObjectWrapper> getContent()
    {
        return content;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaLoader getSchemaLoader()
    {
        return schemaLoader;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder( "\tSchema Name: " );
        sb.append( name );
        sb.append( "\n\t\tDisabled: " );
        sb.append( disabled );
        sb.append( "\n\t\tOwner: " );
        sb.append( owner );
        sb.append( "\n\t\tDependencies: " );
        sb.append( Arrays.toString( dependencies ) );
        sb.append(  "\n\t\tSchemaLoader : " );
        
        if ( schemaLoader != null )
        {
            sb.append( schemaLoader.getClass().getSimpleName() );
        }

        // TODO : print the associated ShcemaObjects
        return sb.toString();
    }
}
