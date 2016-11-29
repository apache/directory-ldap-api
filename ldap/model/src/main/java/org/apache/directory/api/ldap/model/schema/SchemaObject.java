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


import java.util.List;
import java.util.Map;


/**
 * Most schema objects have some common attributes. This class
 * contains the minimum set of properties exposed by a SchemaObject.<br>
 * We have 11 types of SchemaObjects :
 * <ul>
 *   <li> AttributeType </li>
 *   <li> DitCOntentRule </li>
 *   <li> DitStructureRule </li>
 *   <li> LdapComparator (specific to ADS) </li>
 *   <li> LdapSyntaxe </li>
 *   <li> MatchingRule </li>
 *   <li> MatchingRuleUse </li>
 *   <li> NameForm </li>
 *   <li> Normalizer (specific to ADS) </li>
 *   <li> ObjectClass </li>
 *   <li> SyntaxChecker (specific to ADS) </li>
 * </ul>
 * <br>
 * <br>
 * This class provides accessors and setters for the following attributes,
 * which are common to all those SchemaObjects :
 * <ul>
 *   <li>oid : The numeric OID </li>
 *   <li>description : The SchemaObject description </li>
 *   <li>obsolete : Tells if the schema object is obsolete </li>
 *   <li>extensions : The extensions, a key/Values map </li>
 *   <li>schemaObjectType : The SchemaObject type (see upper) </li>
 *   <li>schema : The schema the SchemaObject is associated with (it's an extension).
 *   Can be null </li>
 *   <li>isEnabled : The SchemaObject status (it's related to the schema status) </li>
 *   <li>isReadOnly : Tells if the SchemaObject can be modified or not </li>
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
public interface SchemaObject
{
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
    String getOid();


    /**
     * A special method used when renaming an SchemaObject: we may have to
     * change it's OID
     * @param oid The new OID
     */
    void setOid( String oid );


    /**
     * Gets short names for this SchemaObject if any exists for it, otherwise,
     * returns an empty list.
     * 
     * @return the names for this SchemaObject
     */
    List<String> getNames();


    /**
     * Gets the first name in the set of short names for this SchemaObject if
     * any exists for it.
     * 
     * @return the first of the names for this SchemaObject or the oid
     * if one does not exist
     */
    String getName();


    /**
     * Add a new name to the list of names for this SchemaObject. The name
     * is lower cased and trimmed.
     * 
     * @param names The names to add
     */
    void addName( String... names );


    /**
     * Sets the list of names for this SchemaObject. The names are
     * lower cased and trimmed.
     * 
     * @param names The list of names. Can be empty
     */
    void setNames( List<String> names );


    /**
     * Gets a short description about this SchemaObject.
     * 
     * @return a short description about this SchemaObject
     */
    String getDescription();


    /**
     * Sets the SchemaObject's description
     * 
     * @param description The SchemaObject's description
     */
    void setDescription( String description );


    /**
     * Gets the SchemaObject specification.
     * 
     * @return the SchemaObject specification
     */
    String getSpecification();


    /**
     * Sets the SchemaObject's specification
     * 
     * @param specification The SchemaObject's specification
     */
    void setSpecification( String specification );


    /**
     * Tells if this SchemaObject is enabled.
     * 
     * @return true if the SchemaObject is enabled, or if it depends on
     * an enabled schema
     */
    boolean isEnabled();


    /**
     * Tells if this SchemaObject is disabled.
     * 
     * @return true if the SchemaObject is disabled
     */
    boolean isDisabled();


    /**
     * Sets the SchemaObject state, either enabled or disabled.
     * 
     * @param enabled The current SchemaObject state
     */
    void setEnabled( boolean enabled );


    /**
     * Tells if this SchemaObject is ReadOnly.
     * 
     * @return true if the SchemaObject is not modifiable
     */
    boolean isReadOnly();


    /**
     * Sets the SchemaObject readOnly flag
     * 
     * @param isReadOnly The current SchemaObject ReadOnly status
     */
    void setReadOnly( boolean isReadOnly );


    /**
     * Gets whether or not this SchemaObject has been inactivated. All
     * SchemaObjects except Syntaxes allow for this parameter within their
     * definition. For Syntaxes this property should always return false in
     * which case it is never included in the description.
     * 
     * @return true if inactive, false if active
     */
    boolean isObsolete();


    /**
     * Sets the Obsolete flag.
     * 
     * @param obsolete The Obsolete flag state
     */
    void setObsolete( boolean obsolete );


    /**
     * @return The SchemaObject extensions, as a Map of [extension, values]
     */
    Map<String, List<String>> getExtensions();


    /**
     * Check if a given extension is part of the SchemaObject. Extensions are case insensitive.
     * 
     * @param extension The extension we are looking for.
     * @return <code>true</code> if the extension is present.
     */
    boolean hasExtension( String extension );


    /**
     * Get back the values associated with a given extension.
     * 
     * @param extension The extension we are looking for.
     * @return The list of values associated with the extension
     */
    List<String> getExtension( String extension );


    /**
     * Add an extension with its values
     * @param key The extension key
     * @param values The associated values
     */
    void addExtension( String key, String... values );


    /**
     * Add an extension with its values
     * @param key The extension key
     * @param values The associated values
     */
    void addExtension( String key, List<String> values );


    /**
     * Add an extensions with their values. (Actually do a copy)
     * 
     * @param extensions The extensions map
     */
    void setExtensions( Map<String, List<String>> extensions );


    /**
     * The SchemaObject type :
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
     * 
     * @return the SchemaObject type
     */
    SchemaObjectType getObjectType();


    /**
     * Gets the name of the schema this SchemaObject is associated with.
     *
     * @return the name of the schema associated with this schemaObject
     */
    String getSchemaName();


    /**
     * Sets the name of the schema this SchemaObject is associated with.
     * 
     * @param schemaName the new schema name
     */
    void setSchemaName( String schemaName );


    /**
     * {@inheritDoc}
     */
    @Override
    int hashCode();


    /**
     * {@inheritDoc}
     */
    @Override
    boolean equals( Object o1 );


    /**
     * Copy the current SchemaObject on place
     *
     * @return The copied SchemaObject
     */
    SchemaObject copy();


    /**
     * Copies the given schema object into this schema object.
     *
     * @param original the original SchemaObject
     * @return this
     */
    SchemaObject copy( SchemaObject original );


    /**
     * Clear the current SchemaObject : remove all the references to other objects,
     * and all the Maps.
     */
    void clear();


    /**
     * Transform the SchemaObject to an immutable object
     *
     */
    void lock();
}
