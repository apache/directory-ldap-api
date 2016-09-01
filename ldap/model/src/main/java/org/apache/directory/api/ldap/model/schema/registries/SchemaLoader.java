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
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * Loads schemas into registries.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SchemaLoader
{
    /**
     * Gets a schema object based on it's name.
     * 
     * @param schemaName the name of the schema to load
     * @return the Schema object associated with the name
     */
    Schema getSchema( String schemaName );


    /**
     * Build a list of AttributeTypes read from the underlying storage for
     * a list of specified schema
     *
     * @param schemas the schemas from which AttributeTypes are loaded
     * @return The list of loaded AttributeTypes
     * @throws LdapException if there are failures accessing AttributeType information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadAttributeTypes( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of AttributeTypes read from the underlying storage for
     * a list of specific schema, using their name
     *
     * @param schemaNames the schema names from which AttributeTypes are loaded
     * @return The list of loaded AttributeTypes
     * @throws LdapException if there are failures accessing AttributeType information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadAttributeTypes( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of Comparators read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which Comparators are loaded
     * @return The list of loaded Comparators
     * @throws LdapException if there are failures accessing Comparator information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadComparators( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of Comparators read from the underlying storage for
     * a list of specific schema, using their name
     *
     * @param schemaNames the schema names from which Comparators are loaded
     * @return The list of loaded Comparators
     * @throws LdapException if there are failures accessing Comparator information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadComparators( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of DitContentRules read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which DitContentRules are loaded
     * @return The list of loaded DitContentRules
     * @throws LdapException if there are failures accessing DitContentRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadDitContentRules( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of DitContentRules read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which DitContentRules are loaded
     * @return The list of loaded DitContentRules
     * @throws LdapException if there are failures accessing DitContentRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadDitContentRules( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of DitStructureRules read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which DitStructureRules are loaded
     * @return The list of loaded DitStructureRules
     * @throws LdapException if there are failures accessing DitStructureRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadDitStructureRules( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of DitStructureRules read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which DitStructureRules are loaded
     * @return The list of loaded DitStructureRules
     * @throws LdapException if there are failures accessing DitStructureRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadDitStructureRules( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of MatchingRules read from the underlying storage for
     * a list of specific schema
     *
     * @param schemas the schemas from which MatchingRules are loaded
     * @return The list of loaded MatchingRules
     * @throws LdapException if there are failures accessing MatchingRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadMatchingRules( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of MatchingRules read from the underlying storage for
     * a list of specific schema, using their name
     *
     * @param schemaNames the schema names from which MatchingRules are loaded
     * @return The list of loaded MatchingRules
     * @throws LdapException if there are failures accessing MatchingRule information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadMatchingRules( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of MatchingRuleUses read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which MatchingRuleUses are loaded
     * @return The list of loaded MatchingRuleUses
     * @throws LdapException if there are failures accessing MatchingRuleUse information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadMatchingRuleUses( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of MatchingRuleUses read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which MatchingRuleUses are loaded
     * @return The list of loaded MatchingRuleUses
     * @throws LdapException if there are failures accessing MatchingRuleUses information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadMatchingRuleUses( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of NameForms read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which NameForms are loaded
     * @return The list of loaded NameForms
     * @throws LdapException if there are failures accessing NameForm information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadNameForms( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of NameForms read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which NameForms are loaded
     * @return The list of loaded NameForms
     * @throws LdapException if there are failures accessing NameForms information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadNameForms( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of Normalizers read from the underlying storage for
     * a list of specified schema
     *
     * @param schemas the schemas from which Normalizers are loaded
     * @return The list of loaded Normalizers
     * @throws LdapException if there are failures accessing Normalizer information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadNormalizers( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of Normalizers read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which Normalizers are loaded
     * @return The list of loaded Normalizers
     * @throws LdapException if there are failures accessing Normalizer information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadNormalizers( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of ObjectClasses read from the underlying storage for
     * a list of specific schema.
     *
     * @param schemas the schemas from which ObjectClasses are loaded
     * @return The list of loaded ObjectClasses
     * @throws LdapException if there are failures accessing ObjectClass information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadObjectClasses( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of ObjectClasses read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which ObjectClasses are loaded
     * @return The list of loaded ObjectClasses
     * @throws LdapException if there are failures accessing ObjectClasses information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadObjectClasses( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of Syntaxes read from the underlying storage for
     * a list of specified schema
     *
     * @param schemas the schemas from which Syntaxes are loaded
     * @return The list of loaded Syntaxes
     * @throws LdapException if there are failures accessing Syntax information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadSyntaxes( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of Syntaxes read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which Syntaxes are loaded
     * @return The list of loaded Syntaxes
     * @throws LdapException if there are failures accessing Syntax information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadSyntaxes( String... schemaNames ) throws LdapException, IOException;


    /**
     * Build a list of SyntaxCheckers read from the underlying storage for
     * a list of specified schema
     *
     * @param schemas the schemas from which SyntaxCheckers are loaded
     * @return The list of loaded SyntaxeCheckers
     * @throws LdapException if there are failures accessing SyntaxChecker information
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadSyntaxCheckers( Schema... schemas ) throws LdapException, IOException;


    /**
     * Build a list of SyntaxCheckers read from the underlying storage for
     * a list of specified schema names
     *
     * @param schemaNames the schema names from which SyntaxCheckers are loaded
     * @return A list of loaded SyntaxCheckers
     * @throws LdapException if there are failures accessing SyntaxChecker information
     * @throws IOException If we had some issues loading the schemas
     * @throws IOException If we can't read the schemaObject
     */
    List<Entry> loadSyntaxCheckers( String... schemaNames ) throws LdapException, IOException;


    /**
     * @return the list of enabled schemas
     */
    Collection<Schema> getAllEnabled();


    /**
     * @return the list of all schemas
     */
    Collection<Schema> getAllSchemas();


    /**
     * Add a new schema to the schema's list
     * 
     * @param schema The schema to add
     */
    void addSchema( Schema schema );


    /**
     * Remove a schema from the schema's list
     * 
     * @param schema The schema to remove
     */
    void removeSchema( Schema schema );
    
    
    /**
     * @return Tells if the SchemaLoader is in RELAXED mode
     */
    boolean isRelaxed();
    
    
    /**
     * @return Tells if the SchemaLoader is in STRICT mode
     */
    boolean isStrict();
    
    
    /**
     * Set the SchemzLoader in STRICT or RELAXED mode.
     * 
     * @param relaxed if <code>true</code>, the SchemaLoader will be in relaxed mode, otherwise
     * it will be in strict mode (the default)
     */
    void setRelaxed( boolean relaxed );
}
