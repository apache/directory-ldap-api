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
package org.apache.directory.shared.ldap.model.schema;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.registries.Registries;
import org.apache.directory.shared.util.Strings;


/**
 * Most schema objects have some common attributes. This class
 * contains the minimum set of properties exposed by a SchemaObject.<br> 
 * We have 11 types of SchemaObjects :
 * <li> AttributeType
 * <li> DitCOntentRule
 * <li> DitStructureRule
 * <li> LdapComparator (specific to ADS)
 * <li> LdapSyntaxe
 * <li> MatchingRule
 * <li> MatchingRuleUse
 * <li> NameForm
 * <li> Normalizer (specific to ADS)
 * <li> ObjectClass
 * <li> SyntaxChecker (specific to ADS)
 * <br>
 * <br>
 * This class provides accessors and setters for the following attributes, 
 * which are common to all those SchemaObjects :
 * <li>oid : The numeric OID 
 * <li>description : The SchemaObject description
 * <li>obsolete : Tells if the schema object is obsolete
 * <li>extensions : The extensions, a key/Values map
 * <li>schemaObjectType : The SchemaObject type (see upper)
 * <li>schema : The schema the SchemaObject is associated with (it's an extension).
 * Can be null
 * <li>isEnabled : The SchemaObject status (it's related to the schema status)
 * <li>isReadOnly : Tells if the SchemaObject can be modified or not
 * <br><br>
 * Some of those attributes are not used by some Schema elements, even if they should
 * have been used. Here is the list :
 * <b>name</b> : LdapSyntax, Comparator, Normalizer, SyntaxChecker
 * <b>numericOid</b> : DitStructureRule, 
 * <b>obsolete</b> : LdapSyntax, Comparator, Normalizer, SyntaxChecker
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractMutableSchemaObject extends AbstractSchemaObject implements MutableSchemaObject, Serializable
{
    private static final long serialVersionUID = 1L;

    /** A locked to avoid modifications when set to true */
    protected volatile boolean locked;
    
    /**
     * A constructor for a SchemaObject instance. It must be
     * invoked by the inherited class.
     *
     * @param objectType The SchemaObjectType to create
     * @param oid the SchemaObject numeric OID
     */
    protected AbstractMutableSchemaObject( SchemaObjectType objectType, String oid )
    {
        this.objectType = objectType;
        this.oid = oid;
        extensions = new HashMap<String, List<String>>();
        names = new ArrayList<String>();
    }


    /**
     * Constructor used when a generic reusable SchemaObject is assigned an
     * OID after being instantiated.
     * 
     * @param objectType The SchemaObjectType to create
     */
    protected AbstractMutableSchemaObject( SchemaObjectType objectType )
    {
        this.objectType = objectType;
        extensions = new HashMap<String, List<String>>();
        names = new ArrayList<String>();
    }


    /**
     * A special method used when renaming an SchemaObject: we may have to
     * change it's OID
     * @param oid The new OID
     */
    public void setOid( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        this.oid = oid;
    }


    /**
     * {@inheritDoc}
     */
    public void addToRegistries( List<Throwable> errors, Registries registries ) throws LdapException
    {
        // do nothing
    }


    /**
     * {@inheritDoc}
     */
    public void removeFromRegistries( List<Throwable> errors, Registries registries ) throws LdapException
    {
        // do nothing
    }


    /**
     * Inject the Registries into the SchemaObject
     *
     * @param registries The Registries
     */
    public void setRegistries( Registries registries )
    {
        // do nothing
    }


    /**
     * Add a new name to the list of names for this SchemaObject. The name
     * is lowercased and trimmed.
     *  
     * @param namesToAdd The names to add
     */
    public void addName( String... namesToAdd )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            // We must avoid duplicated names, as names are case insensitive
            Set<String> lowerNames = new HashSet<String>();

            // Fills a set with all the existing names
            for ( String name : this.names )
            {
                lowerNames.add( Strings.toLowerCase(name) );
            }

            for ( String name : namesToAdd )
            {
                if ( name != null )
                {
                    String lowerName = Strings.toLowerCase(name);
                    // Check that the lower cased names is not already present
                    if ( !lowerNames.contains( lowerName ) )
                    {
                        this.names.add( name );
                        lowerNames.add( lowerName );
                    }
                }
            }
        }
    }


    /**
     * Sets the list of names for this SchemaObject. The names are
     * lowercased and trimmed.
     *  
     * @param names The list of names. Can be empty
     */
    public void setNames( List<String> names )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( names == null )
        {
            return;
        }

        if ( !isReadOnly )
        {
            this.names = new ArrayList<String>( names.size() );

            for ( String name : names )
            {
                if ( name != null )
                {
                    this.names.add( name );
                }
            }
        }
    }


    /**
     * Sets the list of names for this SchemaObject. The names are
     * lowercased and trimmed.
     *  
     * @param names The list of names.
     */
    public void setNames( String... names )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( names == null )
        {
            return;
        }

        if ( !isReadOnly )
        {
            this.names.clear();
            
            for ( String name : names )
            {
                if ( name != null )
                {
                    this.names.add( name );
                }
            }
        }
    }


    /**
     * Sets the SchemaObject's description
     * 
     * @param description The SchemaObject's description
     */
    public void setDescription( String description )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            this.description = description;
        }
    }


    /**
     * Sets the SchemaObject's specification
     * 
     * @param specification The SchemaObject's specification
     */
    public void setSpecification( String specification )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            this.specification = specification;
        }
    }


    /**
     * Sets the SchemaObject state, either enabled or disabled.
     * 
     * @param enabled The current SchemaObject state
     */
    public void setEnabled( boolean enabled )
    {
        if ( !isReadOnly )
        {
            isEnabled = enabled;
        }
    }


    /**
     * Sets the SchemaObject readOnly flag
     * 
     * @param readOnly The current SchemaObject ReadOnly status
     */
    public void setReadOnly( boolean readOnly )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        this.isReadOnly = readOnly;
    }


    /**
     * Sets the Obsolete flag.
     * 
     * @param obsolete The Obsolete flag state
     */
    public void setObsolete( boolean obsolete )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            this.isObsolete = obsolete;
        }
    }


    /**
     * Add an extension with its values
     * @param key The extension key
     * @param values The associated values
     */
    public void addExtension( String key, List<String> values )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            extensions.put( key, values );
        }
    }


    /**
     * Add an extensions with their values. (Actually do a copy)
     * 
     * @param extensions The extensions map
     */
    public void setExtensions( Map<String, List<String>> extensions )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly && ( extensions != null ) )
        {
            this.extensions = new HashMap<String, List<String>>();

            for ( String key : extensions.keySet() )
            {
                List<String> values = new ArrayList<String>();

                for ( String value : extensions.get( key ) )
                {
                    values.add( value );
                }

                this.extensions.put( key, values );
            }

        }
    }


    /**
     * Sets the name of the schema this SchemaObject is associated with.
     * 
     * @param schemaName the new schema name
     */
    public void setSchemaName( String schemaName )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }
        
        if ( !isReadOnly )
        {
            this.schemaName = schemaName;
        }
    }


    /**
     * Register the given SchemaObject into the given registries' globalOidRegistry
     *
     * @param schemaObject the SchemaObject we want to register
     * @param registries The registries in which we want it to be stored
     * @throws LdapException If the OID is invalid
     */
    public void registerOid( MutableSchemaObject schemaObject, Registries registries ) throws LdapException
    {
        // Add the SchemaObject into the globalOidRegistry
        registries.getGlobalOidRegistry().register( schemaObject );
    }


    /**
     * {@inheritDoc}
     */
    public SchemaObject copy( SchemaObject original )
    {
        // copy the description
        description = original.getDescription();

        // copy the flags
        isEnabled = original.isEnabled();
        isObsolete = original.isObsolete();
        isReadOnly = original.isReadOnly();

        // copy the names
        names = new ArrayList<String>();

        for ( String name : original.getNames() )
        {
            names.add( name );
        }

        // copy the extensions
        extensions = new HashMap<String, List<String>>();

        for ( String key : original.getExtensions().keySet() )
        {
            List<String> extensionValues = original.getExtensions().get( key );

            List<String> cloneExtension = new ArrayList<String>();

            for ( String value : extensionValues )
            {
                cloneExtension.add( value );
            }

            extensions.put( key, cloneExtension );
        }

        // The SchemaName
        schemaName = original.getSchemaName();

        // The specification
        specification = original.getSpecification();

        return this;
    }


    /**
     * Clear the current SchemaObject : remove all the references to other objects, 
     * and all the Maps. 
     */
    public void clear()
    {
        // Clear the extensions
        for ( String extension : extensions.keySet() )
        {
            List<String> extensionList = extensions.get( extension );

            extensionList.clear();
        }

        extensions.clear();

        // Clear the names
        names.clear();
    }
    

    /**
     * {@inheritDoc}
     */
    public final void lock()
    {
        if ( locked )
        {
            return;
        }
        
        h = 37;

        // The OID
        h += h * 17 + oid.hashCode();

        // The SchemaObject type
        h += h * 17 + objectType.getValue();

        // The Names, if any
        if ( ( names != null ) && ( names.size() != 0 ) )
        {
            for ( String name : names )
            {
                h += h * 17 + name.hashCode();
            }
        }

        // The schemaName if any
        if ( schemaName != null )
        {
            h += h * 17 + schemaName.hashCode();
        }

        h += h * 17 + ( isEnabled ? 1 : 0 );
        h += h * 17 + ( isReadOnly ? 1 : 0 );

        // The description, if any
        if ( description != null )
        {
            h += h * 17 + description.hashCode();
        }

        // The extensions, if any
        for ( String key : extensions.keySet() )
        {
            h += h * 17 + key.hashCode();

            List<String> values = extensions.get( key );

            if ( values != null )
            {
                for ( String value : values )
                {
                    h += h * 17 + value.hashCode();
                }
            }
        }
        
        locked = true;
    }
}
