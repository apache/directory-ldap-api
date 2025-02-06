/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.schema.loader;


import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescription;
import org.apache.directory.api.ldap.model.schema.parsers.NormalizerDescription;
import org.apache.directory.api.ldap.model.schema.parsers.SyntaxCheckerDescription;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;


/**
 * An interface to be implemented by classes needed to create Schema elements. The factory
 * will creates schema elements based on an Entry.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface EntityFactory
{
    /**
     * Return an instance of the Schema associated to the entry
     *
     * @param entry The Schema entry
     * @return An instance of a Schema
     * @throws LdapException If the instance can't be created
     */
    Schema getSchema( Entry entry ) throws LdapException;


    /**
     * Construct an AttributeType from an entry representing an AttributeType.
     *
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build an AttributeType
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return An AttributeType SchemaObject
     * @throws LdapException If the AttributeType is invalid
     */
    AttributeType getAttributeType( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException;


    /**
     * Construct a LdapComparator from a description of a comparator.
     *
     * @param schemaManager The Schema Manager
     * @param comparatorDescription The LdapComparator description object 
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return A new instance of a LdapComparator
     * @throws LdapException If the creation has failed
     */
    LdapComparator<?> getLdapComparator( SchemaManager schemaManager,
        LdapComparatorDescription comparatorDescription,
        Registries targetRegistries, String schemaName ) throws LdapException;


    /**
     * Retrieve and load a Comparator class from the DIT.
     * 
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build a LdapComparator
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return the loaded Comparator
     * @throws LdapException if anything fails during loading
     */
    LdapComparator<?> getLdapComparator( SchemaManager schemaManager, Entry entry,
        Registries targetRegistries, String schemaName ) throws LdapException;


    /**
     * Construct an MatchingRule from an entry get from the Dit
     *
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build a MatchingRule
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return A MatchingRule SchemaObject
     * @throws LdapException If the MatchingRule is invalid
     */
    MatchingRule getMatchingRule( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException;


    /**
     * Create a new instance of a Normalizer 
     *
     * @param schemaManager The Schema Manager
     * @param normalizerDescription The Normalizer description object 
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return A new instance of a normalizer
     * @throws LdapException If the creation has failed
     */
    Normalizer getNormalizer( SchemaManager schemaManager, NormalizerDescription normalizerDescription,
        Registries targetRegistries, String schemaName ) throws LdapException;


    /**
     * Retrieve and load a Normalizer class from the DIT.
     * 
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build a Normalizer
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return the loaded Normalizer
     * @throws LdapException if anything fails during loading
     */
    Normalizer getNormalizer( SchemaManager schemaManager, Entry entry, Registries targetRegistries, String schemaName )
        throws LdapException;


    /**
     * Retrieve and load an ObjectClass  from the DIT
     * 
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build an ObjectClass
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return The loaded ObjectClass
     * @throws LdapException if anything fails during loading
     */
    ObjectClass getObjectClass( SchemaManager schemaManager, Entry entry, Registries targetRegistries, String schemaName )
        throws LdapException;


    /**
     * Retrieve and load an LdapSyntax  from the DIT
     * 
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build a LdapSyntax
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return The loaded Syntax
     * @throws LdapException if anything fails during loading
     */
    LdapSyntax getSyntax( SchemaManager schemaManager, Entry entry, Registries targetRegistries, String schemaName )
        throws LdapException;


    /**
     * Retrieve and load a syntaxChecker class from the DIT.
     * 
     * @param schemaManager The Schema Manager
     * @param entry The entry containing all the informations to build a SyntaxChecker
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return the loaded SyntaxChecker
     * @throws LdapException if anything fails during loading
     */
    SyntaxChecker getSyntaxChecker( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException;


    /**
     * Create a new instance of a SyntaxChecker 
     *
     * @param schemaManager The Schema Manager
     * @param syntaxCheckerDescription The SyntaxChecker description object 
     * @param targetRegistries The registries containing all the enabled SchemaObjects
     * @param schemaName The schema this SchemaObject will be part of
     * @return A new instance of a syntaxChecker
     * @throws LdapException If the creation has failed
     */
    SyntaxChecker getSyntaxChecker( SchemaManager schemaManager, SyntaxCheckerDescription syntaxCheckerDescription,
        Registries targetRegistries, String schemaName ) throws LdapException;
}
