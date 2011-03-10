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


import java.util.List;
import java.util.Map;


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
    public abstract String getOid();


    /**
     * Gets short names for this SchemaObject if any exists for it, otherwise,
     * returns an empty list.
     * 
     * @return the names for this SchemaObject
     */
    public abstract List<String> getNames();


    /**
     * Gets the first name in the set of short names for this SchemaObject if
     * any exists for it.
     * 
     * @return the first of the names for this SchemaObject or the oid
     * if one does not exist
     */
    public abstract String getName();


    /**
     * Gets a short description about this SchemaObject.
     * 
     * @return a short description about this SchemaObject
     */
    public abstract String getDescription();


    /**
     * Gets the SchemaObject specification.
     * 
     * @return the SchemaObject specification
     */
    public abstract String getSpecification();


    /**
     * Tells if this SchemaObject is enabled.
     *  
     * @return true if the SchemaObject is enabled, or if it depends on 
     * an enabled schema
     */
    public abstract boolean isEnabled();


    /**
     * Tells if this SchemaObject is disabled.
     *  
     * @return true if the SchemaObject is disabled
     */
    public abstract boolean isDisabled();


    /**
     * Tells if this SchemaObject is ReadOnly.
     *  
     * @return true if the SchemaObject is not modifiable
     */
    public abstract boolean isReadOnly();


    /**
     * Gets whether or not this SchemaObject has been inactivated. All
     * SchemaObjects except Syntaxes allow for this parameter within their
     * definition. For Syntaxes this property should always return false in
     * which case it is never included in the description.
     * 
     * @return true if inactive, false if active
     */
    public abstract boolean isObsolete();


    /**
     * @return The SchemaObject extensions, as a Map of [extension, values]
     */
    public abstract Map<String, List<String>> getExtensions();


    /**
     * Gets the name of the schema this SchemaObject is associated with.
     *
     * @return the name of the schema associated with this schemaObject
     */
    public abstract String getSchemaName();


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
    public abstract SchemaObjectType getObjectType();


    /**
     * Copy the current SchemaObject on place
     *
     * @return The copied SchemaObject
     */
    <R extends SchemaObject> R copy();
}