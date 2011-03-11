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

import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.registries.Registries;


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
public interface MutableSchemaObject extends SchemaObject
{
    /**
     * Sets the Obsolete flag.
     * 
     * @param obsolete The Obsolete flag state
     */
    void setObsolete( boolean obsolete );

    
    /**
     * Copies the given schema object into this schema object.
     *
     * @param original the original SchemaObject
     * @return this
     */
    SchemaObject copy( SchemaObject original );

    
    /**
     * For co-variant return type.
     * 
     * {@inheritDoc}
     */
    MutableSchemaObject copy();
    

    /**
     * Clear the current SchemaObject : remove all the references to other objects, 
     * and all the Maps. 
     */
    void clear();

    
    /**
     * Sets the SchemaObject readOnly flag
     * 
     * @param isReadOnly The current SchemaObject ReadOnly status
     */
    void setReadOnly( boolean isReadOnly );


    /**
     * Sets the SchemaObject state, either enabled or disabled.
     * 
     * @param enabled The current SchemaObject state
     */
    void setEnabled( boolean enabled );


    /**
     * Sets the SchemaObject's description
     * 
     * @param description The SchemaObject's description
     */
    void setDescription( String description );


    /**
     * A special method used when renaming an SchemaObject: we may have to
     * change it's OID
     * @param oid The new OID
     */
    void setOid( String oid );


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
     * Sets the SchemaObject's specification
     * 
     * @param specification The SchemaObject's specification
     */
    void setSpecification( String specification );


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
     * Sets the name of the schema this SchemaObject is associated with.
     * 
     * @param schemaName the new schema name
     */
    void setSchemaName( String schemaName );


    /**
     * Inject this SchemaObject into the given registries, updating the references to
     * other SchemaObject
     *
     * @param errors the errors we got
     * @param registries the registries
     * @throws LdapException if one of the referenced schema objects does not exist
     */
    void addToRegistries( List<Throwable> errors, Registries registries ) throws LdapException;


    /**
     * Remove this SchemaObject from the given registries, updating the references to
     * other SchemaObject.
     *
     * @param errors the errors we got
     * @param registries The registries
     * @throws org.apache.directory.shared.ldap.model.exception.LdapException if one of the referenced schema objects does not exist
     */
    void removeFromRegistries( List<Throwable> errors, Registries registries ) throws LdapException;

    
    /**
     * Inject the Registries into the SchemaObject
     *
     * @param registries The Registries
     */
    void setRegistries( Registries registries );
    
    
    /**
     * Transform the SchemaObject to an immutable object
     * TODO locked.
     *
     */
    void lock();
}
