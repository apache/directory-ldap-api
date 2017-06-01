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


import java.util.Iterator;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.DitStructureRule;


/**
 * An DitStructureRule registry service interface.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface DitStructureRuleRegistry extends SchemaObjectRegistry<DitStructureRule>,
    Iterable<DitStructureRule>
{
    /**
     * Checks to see if an DitStructureRule exists in the registry, by its
     * ruleId. 
     * 
     * @param ruleId the rule identifier of the DitStructureRule
     * @return true if a DitStructureRule definition exists for the ruleId, false
     * otherwise
     */
    boolean contains( int ruleId );


    /**
     * Gets an iterator over the registered descriptions in the registry.
     *
     * @return an Iterator of descriptions
     */
    @Override
    Iterator<DitStructureRule> iterator();


    /**
     * Gets an iterator over the registered ruleId in the registry.
     *
     * @return an Iterator of ruleId
     */
    Iterator<Integer> ruleIdIterator();


    /**
     * Gets the name of the schema this schema object is associated with.
     *
     * @param ruleId the object identifier
     * @return the schema name
     * @throws LdapException if the schema object does not exist
     */
    String getSchemaName( int ruleId ) throws LdapException;


    /**
     * Registers a new DitStructureRule with this registry.
     *
     * @param ditStructureRule the DitStructureRule to register
     * @throws LdapException if the DitStructureRule is already registered or
     * the registration operation is not supported
     */
    @Override
    void register( DitStructureRule ditStructureRule ) throws LdapException;


    /**
     * Looks up an dITStructureRule by its unique Object IDentifier or by its
     * name.
     * 
     * @param ruleId the rule identifier for the DitStructureRule
     * @return the DitStructureRule instance for rule identifier
     * @throws LdapException if the DitStructureRule does not exist
     */
    DitStructureRule lookup( int ruleId ) throws LdapException;


    /**
     * Unregisters a DitStructureRule using it's rule identifier. 
     * 
     * @param ruleId the rule identifier for the DitStructureRule to unregister
     * @throws LdapException if no such DitStructureRule exists
     */
    void unregister( int ruleId ) throws LdapException;


    /**
     * Unregisters all DITStructureRules defined for a specific schema from
     * this registry.
     * 
     * @param schemaName the name of the schema whose syntaxCheckers will be removed from
     * @throws LdapException if no such SchemaElement exists
     */
    @Override
    void unregisterSchemaElements( String schemaName ) throws LdapException;


    /**
     * Modify all the DitStructureRule using a schemaName when this name changes.
     *
     * @param originalSchemaName The original Schema name
     * @param newSchemaName The new Schema name
     * @throws org.apache.directory.api.ldap.model.exception.LdapException if the schema can't be renamed
     */
    @Override
    void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException;


    /**
     * Copy the DitStructureRuleRegistry
     */
    @Override
    DitStructureRuleRegistry copy();
}
