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


import java.util.Collections;
import java.util.List;
import java.util.Map;


public abstract class AbstractSchemaObject implements SchemaObject
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
    /** The hashcode for this schemaObject */
    protected int h;

    
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
    public String getOid()
    {
        return oid;
    }

    /**
     * Gets short names for this SchemaObject if any exists for it, otherwise,
     * returns an empty list.
     * 
     * @return the names for this SchemaObject
     */
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
    public String getName()
    {
        if ( ( names != null ) && ( names.size() != 0 ) )
        {
            return names.get( 0 );
        }
        else
        {
            return oid;
        }
    }

    /**
     * Gets a short description about this SchemaObject.
     * 
     * @return a short description about this SchemaObject
     */
    public String getDescription()
    {
        return description;
    }

    /**
     * Gets the SchemaObject specification.
     * 
     * @return the SchemaObject specification
     */
    public String getSpecification()
    {
        return specification;
    }

    /**
     * Tells if this SchemaObject is enabled.
     *  
     * @return true if the SchemaObject is enabled, or if it depends on 
     * an enabled schema
     */
    public boolean isEnabled()
    {
        return isEnabled;
    }

    /**
     * Tells if this SchemaObject is disabled.
     *  
     * @return true if the SchemaObject is disabled
     */
    public boolean isDisabled()
    {
        return !isEnabled;
    }

    /**
     * Tells if this SchemaObject is ReadOnly.
     *  
     * @return true if the SchemaObject is not modifiable
     */
    public boolean isReadOnly()
    {
        return isReadOnly;
    }

    /**
     * Gets whether or not this SchemaObject has been inactivated. All
     * SchemaObjects except Syntaxes allow for this parameter within their
     * definition. For Syntaxes this property should always return false in
     * which case it is never included in the description.
     * 
     * @return true if inactive, false if active
     */
    public boolean isObsolete()
    {
        return isObsolete;
    }

    /**
     * @return The SchemaObject extensions, as a Map of [extension, values]
     */
    public Map<String, List<String>> getExtensions()
    {
        return extensions;
    }

    /**
     * The SchemaObject type :
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
     * 
     * @return the SchemaObject type
     */
    public SchemaObjectType getObjectType()
    {
        return objectType;
    }

    /**
     * Gets the name of the schema this SchemaObject is associated with.
     *
     * @return the name of the schema associated with this schemaObject
     */
    public String getSchemaName()
    {
        return schemaName;
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
     * @{@inheritDoc}
     */
    @Override
    public boolean equals( Object o1 )
    {
        if ( this == o1 )
        {
            return true;
        }
    
        if ( !( o1 instanceof AbstractMutableSchemaObject ) )
        {
            return false;
        }
    
        AbstractMutableSchemaObject that = ( AbstractMutableSchemaObject ) o1;
    
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
                for ( String key : extensions.keySet() )
                {
                    if ( !that.extensions.containsKey( key ) )
                    {
                        return false;
                    }
    
                    List<String> thisValues = extensions.get( key );
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
     * Copy the current SchemaObject on place
     *
     * @return The copied SchemaObject
     */
    public abstract SchemaObject copy();
    
    
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

}