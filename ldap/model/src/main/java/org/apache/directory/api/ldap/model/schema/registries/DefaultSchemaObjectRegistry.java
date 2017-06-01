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
package org.apache.directory.api.ldap.model.schema.registries;


import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaExceptionCodes;
import org.apache.directory.api.ldap.model.schema.LoadableSchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Common schema object registry interface.
 * 
 * @param <T> The type of SchemaObject
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class DefaultSchemaObjectRegistry<T extends SchemaObject> implements SchemaObjectRegistry<T>,
    Iterable<T>
{
    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultSchemaObjectRegistry.class );

    /** A speedup for debug */
    private static final boolean DEBUG = LOG.isDebugEnabled();

    /** a map of SchemaObject looked up by name */
    protected Map<String, T> byName;

    /** The SchemaObject type, used by the toString() method  */
    protected SchemaObjectType schemaObjectType;

    /** the global OID Registry */
    protected OidRegistry<T> oidRegistry;
    
    /** A flag indicating that the Registry is relaxed or not */
    private boolean isRelaxed;


    /**
     * Creates a new DefaultSchemaObjectRegistry instance.
     * 
     * @param schemaObjectType The Schema Object type
     * @param oidRegistry The OID registry to use
     */
    protected DefaultSchemaObjectRegistry( SchemaObjectType schemaObjectType, OidRegistry<T> oidRegistry )
    {
        byName = new HashMap<>();
        this.schemaObjectType = schemaObjectType;
        this.oidRegistry = oidRegistry;
        this.isRelaxed = Registries.STRICT;
    }
    
    /**
     * Tells if the Registry is permissive or if it must be checked
     * against inconsistencies.
     *
     * @return True if SchemaObjects can be added even if they break the consistency
     */
    public boolean isRelaxed()
    {
        return isRelaxed;
    }


    /**
     * Tells if the Registry is strict.
     *
     * @return True if SchemaObjects cannot be added if they break the consistency
     */
    public boolean isStrict()
    {
        return !isRelaxed;
    }


    /**
     * Change the Registry to a relaxed mode, where invalid SchemaObjects
     * can be registered.
     */
    public void setRelaxed()
    {
        isRelaxed = Registries.RELAXED;
        oidRegistry.setRelaxed();
    }


    /**
     * Change the Registry to a strict mode, where invalid SchemaObjects
     * cannot be registered.
     */
    public void setStrict()
    {
        isRelaxed = Registries.STRICT;
        oidRegistry.setStrict();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        if ( !byName.containsKey( oid ) )
        {
            return byName.containsKey( Strings.toLowerCaseAscii( oid ) );
        }

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        if ( !Oid.isOid( oid ) )
        {
            String msg = I18n.err( I18n.ERR_04267 );
            LOG.warn( msg );
            throw new LdapException( msg );
        }

        SchemaObject schemaObject = byName.get( oid );

        if ( schemaObject != null )
        {
            return schemaObject.getSchemaName();
        }

        String msg = I18n.err( I18n.ERR_04268_OID_NOT_FOUND, oid );
        LOG.warn( msg );
        throw new LdapException( msg );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName )
    {
        // Loop on all the SchemaObjects stored and remove those associated
        // with the give schemaName
        for ( T schemaObject : this )
        {
            if ( originalSchemaName.equalsIgnoreCase( schemaObject.getSchemaName() ) )
            {
                schemaObject.setSchemaName( newSchemaName );

                if ( DEBUG )
                {
                    LOG.debug( "Renamed {} schemaName to {}", schemaObject, newSchemaName );
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<T> iterator()
    {
        return oidRegistry.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return byName.keySet().iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T lookup( String oid ) throws LdapException
    {
        if ( oid == null )
        {
            return null;
        }

        T schemaObject = byName.get( oid );

        if ( schemaObject == null )
        {
            // let's try with trimming and lowercasing now
            schemaObject = byName.get( Strings.trim( Strings.toLowerCaseAscii( oid ) ) );
        }

        if ( schemaObject == null )
        {
            String msg = I18n.err( I18n.ERR_04269, schemaObjectType.name(), oid );
            LOG.debug( msg );
            throw new LdapException( msg );
        }

        if ( DEBUG )
        {
            LOG.debug( "Found {} with oid: {}", schemaObject, oid );
        }

        return schemaObject;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void register( T schemaObject ) throws LdapException
    {
        String oid = schemaObject.getOid();

        if ( byName.containsKey( oid ) )
        {
            String msg = I18n.err( I18n.ERR_04270, schemaObjectType.name(), oid );
            LOG.warn( msg );
            LdapSchemaException ldapSchemaException = new LdapSchemaException(
                LdapSchemaExceptionCodes.OID_ALREADY_REGISTERED, msg );
            ldapSchemaException.setSourceObject( schemaObject );
            throw ldapSchemaException;
        }

        byName.put( oid, schemaObject );

        /*
         * add the aliases/names to the name map along with their toLowerCase
         * versions of the name: this is used to make sure name lookups work
         */
        for ( String name : schemaObject.getNames() )
        {
            String lowerName = Strings.trim( Strings.toLowerCaseAscii( name ) );

            if ( byName.containsKey( lowerName ) )
            {
                String msg = I18n.err( I18n.ERR_04271, schemaObjectType.name(), name );
                LOG.warn( msg );
                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.NAME_ALREADY_REGISTERED, msg );
                ldapSchemaException.setSourceObject( schemaObject );
                throw ldapSchemaException;
            }
            else
            {
                byName.put( lowerName, schemaObject );
            }
        }

        // And register the oid -> schemaObject relation
        oidRegistry.register( schemaObject );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( "registered " + schemaObject.getName() + " for OID {}", oid );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T unregister( String numericOid ) throws LdapException
    {
        if ( !Oid.isOid( numericOid ) )
        {
            String msg = I18n.err( I18n.ERR_04272, numericOid );
            LOG.error( msg );
            throw new LdapException( msg );
        }

        T schemaObject = byName.remove( numericOid );

        for ( String name : schemaObject.getNames() )
        {
            byName.remove( name );
        }

        // And remove the SchemaObject from the oidRegistry
        oidRegistry.unregister( numericOid );

        if ( DEBUG )
        {
            LOG.debug( "Removed {} with oid {} from the registry", schemaObject, numericOid );
        }

        return schemaObject;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T unregister( T schemaObject ) throws LdapException
    {
        String oid = schemaObject.getOid();

        if ( !byName.containsKey( oid ) )
        {
            String msg = I18n.err( I18n.ERR_04273, schemaObjectType.name(), oid );
            LOG.warn( msg );
            throw new LdapException( msg );
        }

        // Remove the oid
        T removed = byName.remove( oid );

        /*
         * Remove the aliases/names from the name map along with their toLowerCase
         * versions of the name.
         */
        for ( String name : schemaObject.getNames() )
        {
            byName.remove( Strings.trim( Strings.toLowerCaseAscii( name ) ) );
        }

        // And unregister the oid -> schemaObject relation
        oidRegistry.unregister( oid );

        return removed;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        if ( schemaName == null )
        {
            return;
        }

        // Loop on all the SchemaObjects stored and remove those associated
        // with the give schemaName
        for ( T schemaObject : this )
        {
            if ( schemaName.equalsIgnoreCase( schemaObject.getSchemaName() ) )
            {
                String oid = schemaObject.getOid();
                SchemaObject removed = unregister( oid );

                if ( DEBUG )
                {
                    LOG.debug( "Removed {} with oid {} from the registry", removed, oid );
                }
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        T schemaObject = byName.get( name );

        if ( schemaObject == null )
        {
            // last resort before giving up check with lower cased version
            String lowerCased = Strings.toLowerCaseAscii( name );

            schemaObject = byName.get( lowerCased );

            // ok this name is not for a schema object in the registry
            if ( schemaObject == null )
            {
                throw new LdapException( I18n.err( I18n.ERR_04274, name ) );
            }
        }

        // we found the schema object by key on the first lookup attempt
        return schemaObject.getOid();
    }


    /**
     * Copy a SchemaObject registry
     * 
     * @param original The SchemaObject registry to copy
     * @return The copied ShcemaObject registry
     */
    // This will suppress PMD.EmptyCatchBlock warnings in this method
    @SuppressWarnings("unchecked")
    public SchemaObjectRegistry<T> copy( SchemaObjectRegistry<T> original )
    {
        // Fill the byName and OidRegistry maps, the type has already be copied
        for ( Map.Entry<String, T> entry : ( ( DefaultSchemaObjectRegistry<T> ) original ).byName.entrySet() )
        {
            String key = entry.getKey();
            // Clone each SchemaObject
            T value = entry.getValue();

            if ( value instanceof LoadableSchemaObject )
            {
                // Update the data structure. 
                // Comparators, Normalizers and SyntaxCheckers aren't copied, 
                // they are immutable
                byName.put( key, value );

                // Update the OidRegistry
                oidRegistry.put( value );
            }
            else
            {
                T copiedValue = null;

                // Copy the value if it's not already in the oidRegistry
                if ( oidRegistry.contains( value.getOid() ) )
                {
                    try
                    {
                        copiedValue = oidRegistry.getSchemaObject( value.getOid() );
                    }
                    catch ( LdapException ne )
                    {
                        // Can't happen
                    }
                }
                else
                {
                    copiedValue = ( T ) value.copy();
                }

                // Update the data structure. 
                byName.put( key, copiedValue );

                // Update the OidRegistry
                oidRegistry.put( copiedValue );
            }
        }

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public T get( String oid )
    {
        try
        {
            return oidRegistry.getSchemaObject( oid );
        }
        catch ( LdapException ne )
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return schemaObjectType;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return oidRegistry.size();
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( schemaObjectType ).append( ": " );
        boolean isFirst = true;

        for ( Map.Entry<String, T> entry : byName.entrySet() )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                sb.append( ", " );
            }

            String name = entry.getKey();
            T schemaObject = entry.getValue();

            sb.append( '<' ).append( name ).append( ", " ).append( schemaObject.getOid() ).append( '>' );
        }

        return sb.toString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear()
    {
        // Clear all the schemaObjects
        for ( SchemaObject schemaObject : oidRegistry )
        {
            // Don't clear LoadableSchemaObject
            if ( !( schemaObject instanceof LoadableSchemaObject ) )
            {
                schemaObject.clear();
            }
        }

        // Remove the byName elements
        byName.clear();

        // Clear the OidRegistry
        oidRegistry.clear();
    }
}
