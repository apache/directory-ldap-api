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
package org.apache.directory.api.ldap.model.schema;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;


/**
 * Most schema objects have some common attributes. This class
 * contains the minimum set of properties exposed by a SchemaObject.<br>
 * We have 11 types of SchemaObjects :
 * <ul>
 *   <li> AttributeType</li>
 *   <li> DitCOntentRule</li>
 *   <li> DitStructureRule</li>
 *   <li> LdapComparator (specific to ADS)</li>
 *   <li> LdapSyntaxe</li>
 *   <li> MatchingRule</li>
 *   <li> MatchingRuleUse</li>
 *   <li> NameForm</li>
 *   <li> Normalizer (specific to ADS)</li>
 *   <li> ObjectClass</li>
 *   <li> SyntaxChecker (specific to ADS)</li>
 * </ul>
 * <br>
 * <br>
 * This class provides accessors and setters for the following attributes,
 * which are common to all those SchemaObjects :
 * <ul>
 *  <li>oid : The numeric OID</li>
 *   <li>description : The SchemaObject description</li>
 *   <li>obsolete : Tells if the schema object is obsolete</li>
 *   <li>extensions : The extensions, a key/Values map</li>
 *   <li>schemaObjectType : The SchemaObject type (see upper)</li>
 *   <li>schema : The schema the SchemaObject is associated with (it's an extension).
 *     Can be null</li>
 *   <li>isEnabled : The SchemaObject status (it's related to the schema status)</li>
 *   <li>isReadOnly : Tells if the SchemaObject can be modified or not</li>
 * </ul>
 * <br><br>
 * Some of those attributes are not used by some Schema elements, even if they should
 * have been used. Here is the list :
 * <ul>
 *   <li><b>name</b> : LdapSyntax, Comparator, Normalizer, SyntaxChecker</li>
 *   <li><b>numericOid</b> : DitStructureRule</li>
 *   <li><b>obsolete</b> : LdapSyntax, Comparator, Normalizer, SyntaxChecker</li>
 * </ul>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractSchemaObject implements SchemaObject, Serializable
{
    /** The serial version UID */
    private static final long serialVersionUID = 2L;

    /** The SchemaObject numeric OID */
    protected String oid;

    /** The optional names for this SchemaObject */
    protected List<String> names;

    /** Whether or not this SchemaObject is enabled */
    protected boolean isEnabled = true;

    /** Whether or not this SchemaObject can be modified */
    protected boolean isReadOnly = false;

    /** Whether or not this SchemaObject is obsolete */
    protected boolean isObsolete = false;

    /** A short description of this SchemaObject */
    protected String description;

    /** The SchemaObject specification */
    protected String specification;

    /** The name of the schema this object is associated with */
    protected String schemaName;

    /** The SchemaObjectType */
    protected SchemaObjectType objectType;

    /** A map containing the list of supported extensions */
    protected Map<String, List<String>> extensions;

    /** A locked to avoid modifications when set to true */
    protected volatile boolean locked;

    /** The hashcode for this schemaObject */
    private int h;


    /**
     * A constructor for a SchemaObject instance. It must be
     * invoked by the inherited class.
     *
     * @param objectType The SchemaObjectType to create
     * @param oid the SchemaObject numeric OID
     */
    protected AbstractSchemaObject( SchemaObjectType objectType, String oid )
    {
        this.objectType = objectType;
        this.oid = oid;
        extensions = new HashMap<>();
        names = new ArrayList<>();
    }


    /**
     * Constructor used when a generic reusable SchemaObject is assigned an
     * OID after being instantiated.
     * 
     * @param objectType The SchemaObjectType to create
     */
    protected AbstractSchemaObject( SchemaObjectType objectType )
    {
        this.objectType = objectType;
        extensions = new HashMap<>();
        names = new ArrayList<>();
    }


    /**
     * Gets usually what is the numeric object identifier assigned to this
     * SchemaObject. All schema objects except for MatchingRuleUses have an OID
     * assigned specifically to then. A MatchingRuleUse's OID really is the OID
     * of it's MatchingRule and not specific to the MatchingRuleUse. This
     * effects how MatchingRuleUse objects are maintained by the system.
     * 
     * @return an OID for this SchemaObject or its MatchingRule if this
     *         SchemaObject is a MatchingRuleUse object
     */
    @Override
    public String getOid()
    {
        return oid;
    }


    /**
     * A special method used when renaming an SchemaObject: we may have to
     * change it's OID
     * @param oid The new OID
     */
    @Override
    public void setOid( String oid )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.oid = oid;
    }


    /**
     * Gets short names for this SchemaObject if any exists for it, otherwise,
     * returns an empty list.
     * 
     * @return the names for this SchemaObject
     */
    @Override
    public List<String> getNames()
    {
        if ( names != null )
        {
            return Collections.unmodifiableList( names );
        }
        else
        {
            return Collections.emptyList();
        }
    }


    /**
     * Gets the first name in the set of short names for this SchemaObject if
     * any exists for it.
     * 
     * @return the first of the names for this SchemaObject or the oid
     * if one does not exist
     */
    @Override
    public String getName()
    {
        if ( ( names != null ) && !names.isEmpty() )
        {
            return names.get( 0 );
        }
        else
        {
            return oid;
        }
    }


    /**
     * Add a new name to the list of names for this SchemaObject. The name
     * is lowercased and trimmed.
     * 
     * @param namesToAdd The names to add
     */
    @Override
    public void addName( String... namesToAdd )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            // We must avoid duplicated names, as names are case insensitive
            Set<String> lowerNames = new HashSet<>();

            // Fills a set with all the existing names
            for ( String name : this.names )
            {
                lowerNames.add( Strings.toLowerCaseAscii( name ) );
            }

            for ( String name : namesToAdd )
            {
                if ( name != null )
                {
                    String lowerName = Strings.toLowerCaseAscii( name );
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
    @Override
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
            this.names = new ArrayList<>( names.size() );

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
     * Gets a short description about this SchemaObject.
     * 
     * @return a short description about this SchemaObject
     */
    @Override
    public String getDescription()
    {
        return description;
    }


    /**
     * Sets the SchemaObject's description
     * 
     * @param description The SchemaObject's description
     */
    @Override
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
     * Gets the SchemaObject specification.
     * 
     * @return the SchemaObject specification
     */
    @Override
    public String getSpecification()
    {
        return specification;
    }


    /**
     * Sets the SchemaObject's specification
     * 
     * @param specification The SchemaObject's specification
     */
    @Override
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
     * Tells if this SchemaObject is enabled.
     * 
     * @return true if the SchemaObject is enabled, or if it depends on
     * an enabled schema
     */
    @Override
    public boolean isEnabled()
    {
        return isEnabled;
    }


    /**
     * Tells if this SchemaObject is disabled.
     * 
     * @return true if the SchemaObject is disabled
     */
    @Override
    public boolean isDisabled()
    {
        return !isEnabled;
    }


    /**
     * Sets the SchemaObject state, either enabled or disabled.
     * 
     * @param enabled The current SchemaObject state
     */
    @Override
    public void setEnabled( boolean enabled )
    {
        if ( !isReadOnly )
        {
            isEnabled = enabled;
        }
    }


    /**
     * Tells if this SchemaObject is ReadOnly.
     * 
     * @return true if the SchemaObject is not modifiable
     */
    @Override
    public boolean isReadOnly()
    {
        return isReadOnly;
    }


    /**
     * Sets the SchemaObject readOnly flag
     * 
     * @param readOnly The current SchemaObject ReadOnly status
     */
    @Override
    public void setReadOnly( boolean readOnly )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        this.isReadOnly = readOnly;
    }


    /**
     * Gets whether or not this SchemaObject has been inactivated. All
     * SchemaObjects except Syntaxes allow for this parameter within their
     * definition. For Syntaxes this property should always return false in
     * which case it is never included in the description.
     * 
     * @return true if inactive, false if active
     */
    @Override
    public boolean isObsolete()
    {
        return isObsolete;
    }


    /**
     * Sets the Obsolete flag.
     * 
     * @param obsolete The Obsolete flag state
     */
    @Override
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
     * {@inheritDoc}
     */
    @Override
    public Map<String, List<String>> getExtensions()
    {
        return extensions;
    }


    /**
     * {@inheritDoc}
     */
    @Override
public boolean hasExtension( String extension )
    {
        return extensions.containsKey( Strings.toUpperCaseAscii( extension ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getExtension( String extension )
    {
        String name = Strings.toUpperCaseAscii( extension );

        if ( hasExtension( name ) )
        {
            for ( Map.Entry<String, List<String>> entry : extensions.entrySet() )
            {
                String key = entry.getKey();
                
                if ( name.equalsIgnoreCase( key ) )
                {
                    return entry.getValue();
                }
            }
        }

        return null;
    }


    /**
     * Add an extension with its values
     * @param key The extension key
     * @param values The associated values
     */
    @Override
    public void addExtension( String key, String... values )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            List<String> valueList = new ArrayList<>();

            for ( String value : values )
            {
                valueList.add( value );
            }

            extensions.put( Strings.toUpperCaseAscii( key ), valueList );
        }
    }


    /**
     * Add an extension with its values
     * @param key The extension key
     * @param values The associated values
     */
    @Override
    public void addExtension( String key, List<String> values )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            extensions.put( Strings.toUpperCaseAscii( key ), values );
        }
    }


    /**
     * Add an extensions with their values. (Actually do a copy)
     * 
     * @param extensions The extensions map
     */
    @Override
    public void setExtensions( Map<String, List<String>> extensions )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly && ( extensions != null ) )
        {
            this.extensions = new HashMap<>();

            for ( Map.Entry<String, List<String>> entry : extensions.entrySet() )
            {
                List<String> values = new ArrayList<>();

                for ( String value : entry.getValue() )
                {
                    values.add( value );
                }

                this.extensions.put( Strings.toUpperCaseAscii( entry.getKey() ), values );
            }

        }
    }


    /**
     * The SchemaObject type :
     * <ul>
     *   <li> AttributeType
     *   <li> DitCOntentRule
     *   <li> DitStructureRule
     *   <li> LdapComparator (specific to ADS)
     *   <li> LdapSyntaxe
     *   <li> MatchingRule
     *   <li> MatchingRuleUse
     *   <li> NameForm
     *   <li> Normalizer (specific to ADS)
     *   <li> ObjectClass
     *   <li> SyntaxChecker (specific to ADS)
     * </ul>
     * 
     * @return the SchemaObject type
     */
    @Override
    public SchemaObjectType getObjectType()
    {
        return objectType;
    }


    /**
     * Gets the name of the schema this SchemaObject is associated with.
     *
     * @return the name of the schema associated with this schemaObject
     */
    @Override
    public String getSchemaName()
    {
        return schemaName;
    }


    /**
     * Sets the name of the schema this SchemaObject is associated with.
     * 
     * @param schemaName the new schema name
     */
    @Override
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
     * This method is final to forbid the inherited classes to implement
     * it. This has been done for performances reasons : the hashcode should
     * be computed only once, and stored locally.
     * 
     * The hashcode is currently computed in the lock() method, which is a hack
     * that should be fixed.
     * 
     * @return {@inheritDoc}
     */
    @Override
    public final int hashCode()
    {
        return h;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o1 )
    {
        if ( this == o1 )
        {
            return true;
        }

        if ( !( o1 instanceof AbstractSchemaObject ) )
        {
            return false;
        }

        AbstractSchemaObject that = ( AbstractSchemaObject ) o1;

        // Two schemaObject are equals if their oid is equal,
        // their ObjectType is equal, their names are equals
        // their schema name is the same, all their flags are equals,
        // the description is the same and their extensions are equals
        if ( !compareOid( oid, that.oid ) )
        {
            return false;
        }

        // Compare the names
        if ( names == null )
        {
            if ( that.names != null )
            {
                return false;
            }
        }
        else if ( that.names == null )
        {
            return false;
        }
        else
        {
            int nbNames = 0;

            for ( String name : names )
            {
                if ( !that.names.contains( name ) )
                {
                    return false;
                }

                nbNames++;
            }

            if ( nbNames != names.size() )
            {
                return false;
            }
        }

        if ( schemaName == null )
        {
            if ( that.schemaName != null )
            {
                return false;
            }
        }
        else
        {
            if ( !schemaName.equalsIgnoreCase( that.schemaName ) )
            {
                return false;
            }
        }

        if ( objectType != that.objectType )
        {
            return false;
        }

        if ( extensions != null )
        {
            if ( that.extensions == null )
            {
                return false;
            }
            else
            {
                for ( Map.Entry<String, List<String>> entry : extensions.entrySet() )
                {
                    String key = entry.getKey();
                    
                    if ( !that.extensions.containsKey( key ) )
                    {
                        return false;
                    }

                    List<String> thisValues = entry.getValue();
                    List<String> thatValues = that.extensions.get( key );

                    if ( thisValues != null )
                    {
                        if ( thatValues == null )
                        {
                            return false;
                        }
                        else
                        {
                            if ( thisValues.size() != thatValues.size() )
                            {
                                return false;
                            }

                            // TODO compare the values
                        }
                    }
                    else if ( thatValues != null )
                    {
                        return false;
                    }
                }
            }
        }
        else if ( that.extensions != null )
        {
            return false;
        }

        if ( this.isEnabled != that.isEnabled )
        {
            return false;
        }

        if ( this.isObsolete != that.isObsolete )
        {
            return false;
        }

        if ( this.isReadOnly != that.isReadOnly )
        {
            return false;
        }

        if ( this.description == null )
        {
            return that.description == null;
        }
        else
        {
            return this.description.equalsIgnoreCase( that.description );
        }
    }


    /**
     * Compare two oids, and return true if they are both null or equal.
     *
     * @param oid1 the first OID
     * @param oid2 the second OID
     * @return <code>true</code> if both OIDs are null or equal
     */
    protected boolean compareOid( String oid1, String oid2 )
    {
        if ( oid1 == null )
        {
            return oid2 == null;
        }
        else
        {
            return oid1.equals( oid2 );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject copy( SchemaObject original )
    {
        // copy the description
        description = original.getDescription();

        // copy the flags
        isEnabled = original.isEnabled();
        isObsolete = original.isObsolete();
        isReadOnly = original.isReadOnly();

        // copy the names
        names = new ArrayList<>();

        for ( String name : original.getNames() )
        {
            names.add( name );
        }

        // copy the extensions
        extensions = new HashMap<>();

        for ( String key : original.getExtensions().keySet() )
        {
            List<String> extensionValues = original.getExtension( key );

            List<String> cloneExtension = new ArrayList<>();

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
    @Override
    public void clear()
    {
        // Clear the extensions
        for ( Map.Entry<String, List<String>> entry : extensions.entrySet() )
        {
            List<String> extensionList = entry.getValue();

            extensionList.clear();
        }

        extensions.clear();

        // Clear the names
        names.clear();
    }


    /**
     * Unlock the Schema Object and make it modifiable again.
     */
    public void unlock()
    {
        locked = false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
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
        if ( ( names != null ) && !names.isEmpty() )
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
        for ( Map.Entry<String, List<String>> entry : extensions.entrySet() )
        {
            String key = entry.getKey();
            h += h * 17 + key.hashCode();

            List<String> values = entry.getValue();

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
