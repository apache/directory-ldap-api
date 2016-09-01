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


import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.normalizers.OidNormalizer;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ComparatorRegistry;
import org.apache.directory.api.ldap.model.schema.registries.DitContentRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.DitStructureRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.LdapSyntaxRegistry;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleUseRegistry;
import org.apache.directory.api.ldap.model.schema.registries.NameFormRegistry;
import org.apache.directory.api.ldap.model.schema.registries.NormalizerRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.OidRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.model.schema.registries.SyntaxCheckerRegistry;


/**
 * A class used to manage access to the Schemas and Registries. It's associated 
 * with a SchemaLoader, in charge of loading the schemas from the disk.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SchemaManager
{
    /** Two flags for RELAXED and STRICT, this is STRICT */
    boolean STRICT = false;

    /** Two flags for RELAXED and STRICT, this is RELAXED */
    boolean RELAXED = true;

    //---------------------------------------------------------------------------------
    // Schema loading methods
    //---------------------------------------------------------------------------------
    /**
     * Load some Schemas into the registries. The Registries is checked after the 
     * schemas have been loaded, and if there is an error, the method returns false
     * and the registries is kept intact.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas to load
     * @return true if the schemas have been loaded and the registries is consistent
     * @throws LdapException If something went wrong
     */
    boolean load( Schema... schemas ) throws LdapException;


    /**
     * Load some Schemas into the registries. The Registries is checked after the 
     * schemas have been loaded, and if there is an error, the method returns false
     * and the registries is kept intact.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas' name to load
     * @return true if the schemas have been loaded and the registries is consistent
     * @throws LdapException If something went wrong
     */
    boolean load( String... schemas ) throws LdapException;


    /**
     * Load some Schemas into the registries, and loads all of the schemas they depend
     * on. The Registries is checked after the schemas have been loaded, and if there 
     * is an error, the method returns false and the registries is kept intact.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas to load
     * @return true if the schemas have been loaded and the registries is consistent
     * @throws LdapException If something went wrong
     */
    boolean loadWithDeps( Schema... schemas ) throws LdapException;


    /**
     * Load some Schemas into the registries, and loads all of the schemas they depend
     * on. The Registries is checked after the schemas have been loaded, and if there 
     * is an error, the method returns false and the registries is kept intact.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas' name to load
     * @return true if the schemas have been loaded and the registries is consistent
     * @throws LdapException If something went wrong
     */
    boolean loadWithDeps( String... schemas ) throws LdapException;


    /**
     * Load Schemas into the registries, even if there are some errors in the schemas. 
     * The Registries is checked after the schemas have been loaded. Even if we have 
     * errors, the registries will be updated.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas to load, if enabled
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadRelaxed( Schema... schemas ) throws LdapException;


    /**
     * Load Schemas into the registries, even if there are some errors in the schemas. 
     * The Registries is checked after the schemas have been loaded. Even if we have 
     * errors, the registries will be updated.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas' name to load, if enabled
     * @return true if the schemas have been loaded and the registries is consistent
     * @throws LdapException If something went wrong
     */
    boolean loadRelaxed( String... schemas ) throws LdapException;


    /**
     * Load some Schemas into the registries, and loads all of the schemas they depend
     * on. The Registries is checked after the schemas have been loaded. Even if we have 
     * errors, the registries will be updated.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas to load
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadWithDepsRelaxed( Schema... schemas ) throws LdapException;


    /**
     * Load some Schemas into the registries, and loads all of the schemas they depend
     * on. The Registries is checked after the schemas have been loaded. Even if we have 
     * errors, the registries will be updated.
     * <br>
     * The Schemas must be enabled, and only enabled SchemaObject will be loaded.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     * 
     * @param schemas the Schemas' name to load
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadWithDepsRelaxed( String... schemas ) throws LdapException;


    /**
     * Load Schemas into the Registries, even if they are disabled. The disabled
     * SchemaObject from an enabled schema will also be loaded. The Registries will
     * be checked after the schemas have been loaded. Even if we have errors, the
     * Registries will be updated.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     *
     * @param schemas The Schemas to load
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadDisabled( Schema... schemas ) throws LdapException;


    /**
     * Load Schemas into the Registries, even if they are disabled. The disabled
     * SchemaObject from an enabled schema will also be loaded. The Registries will
     * be checked after the schemas have been loaded. Even if we have errors, the
     * Registries will be updated.
     * <br>
     * If any error was met, the {@link #getErrors} method will contain them
     *
     * @param schemas The Schemas' name to load
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadDisabled( String... schemas ) throws LdapException;


    /**
     * Load all the enabled schema into the Registries. The Registries is strict,
     * any inconsistent schema will be rejected. 
     *
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadAllEnabled() throws LdapException;


    /**
     * Load all the enabled schema into the Registries. The Registries is relaxed,
     * even inconsistent schema will be loaded. 
     *
     * @return true if the schemas have been loaded
     * @throws LdapException If something went wrong
     */
    boolean loadAllEnabledRelaxed() throws LdapException;


    /**
     * Unload the given set of Schemas
     *
     * @param schemas The list of Schema to unload
     * @return True if all the schemas have been unloaded
     * @throws LdapException If something went wrong
     */
    boolean unload( Schema... schemas ) throws LdapException;


    /**
     * Unload the given set of Schemas
     *
     * @param schemas The list of Schema to unload
     * @return True if all the schemas have been unloaded
     * @throws LdapException If something went wrong
     */
    boolean unload( String... schemas ) throws LdapException;


    //---------------------------------------------------------------------------------
    // Other Schema methods
    //---------------------------------------------------------------------------------
    /**
     * Enables a set of Schemas, and returns true if all the schema have been
     * enabled, with all the dependent schemas, and if the registries is 
     * still consistent.
     * 
     * If the modification is ok, the Registries will be updated. 
     * 
     * @param schemas The list of schemas to enable
     * @return true if the Registries is still consistent, false otherwise.
     * @throws LdapException If something went wrong
     */
    boolean enable( Schema... schemas ) throws LdapException;


    /**
     * Enables a set of Schemas, and returns true if all the schema have been
     * enabled, with all the dependent schemas, and if the registries is 
     * still consistent.
     * 
     * If the modification is ok, the Registries will be updated.
     *  
     * @param schemas The list of schema name to enable
     * @return true if the Registries is still consistent, false otherwise.
     * @throws LdapException If something went wrong
     */
    boolean enable( String... schemas ) throws LdapException;


    /**
     * Enables a set of Schemas, and returns true if all the schema have been
     * enabled, with all the dependent schemas. No check is done, the Registries
     * might become inconsistent after this operation.
     * 
     * @param schemas The list of schemas to enable
     * @return true if all the schemas have been enabled
     */
    boolean enableRelaxed( Schema... schemas );


    /**
     * Enables a set of Schemas, and returns true if all the schema have been
     * enabled, with all the dependent schemas. No check is done, the Registries
     * might become inconsistent after this operation.
     * 
     * @param schemas The list of schema names to enable
     * @return true if all the schemas have been enabled
     */
    boolean enableRelaxed( String... schemas );


    /**
     * @return the list of all the enabled schema
     */
    Collection<Schema> getEnabled();


    /**
     * @return the list of all schemas
     */
    Collection<Schema> getAllSchemas();


    /**
     * Tells if the given Schema is enabled
     *
     * @param schemaName The schema name
     * @return true if the schema is enabled
     */
    boolean isEnabled( String schemaName );


    /**
     * Tells if the given Schema is enabled
     *
     * @param schema The schema
     * @return true if the schema is enabled
     */
    boolean isEnabled( Schema schema );


    /**
     * Disables a set of Schemas, and returns true if all the schema have been
     * disabled, with all the dependent schemas, and if the registries is 
     * still consistent.
     * 
     * If the modification is ok, the Registries will be updated. 
     * 
     *  @param schemas The list of schemas to disable
     *  @return true if the Registries is still consistent, false otherwise.
     *  @throws LdapException If something went wrong
     */
    boolean disable( Schema... schemas ) throws LdapException;


    /**
     * Disables a set of Schemas, and returns true if all the schema have been
     * disabled, with all the dependent schemas, and if the registries is 
     * still consistent.
     * 
     * If the modification is ok, the Registries will be updated. 
     * 
     *  @param schemas The list of schema names to disable
     *  @return true if the Registries is still consistent, false otherwise.
     *  @throws LdapException If something went wrong
     */
    boolean disable( String... schemas ) throws LdapException;


    /**
     * Disables a set of Schemas, and returns true if all the schema have been
     * disabled, with all the dependent schemas. The Registries is not checked
     * and can be inconsistent after this operation
     * 
     * If the modification is ok, the Registries will be updated. 
     * 
     *  @param schemas The list of schemas to disable
     *  @return true if all the schemas have been disabled
     */
    boolean disabledRelaxed( Schema... schemas );


    /**
     * Disables a set of Schemas, and returns true if all the schema have been
     * disabled, with all the dependent schemas. The Registries is not checked
     * and can be inconsistent after this operation
     * 
     * If the modification is ok, the Registries will be updated. 
     * 
     *  @param schemas The list of schema names to disable
     *  @return true if all the schemas have been disabled
     */
    boolean disabledRelaxed( String... schemas );


    /**
     * @return the list of all the disabled schema
     */
    List<Schema> getDisabled();


    /**
     * Tells if the given Schema is disabled
     *
     * @param schemaName The schema name
     * @return true if the schema is disabled
     */
    boolean isDisabled( String schemaName );


    /**
     * Tells if the given Schema is disabled
     *
     * @param schema The schema
     * @return true if the schema is disabled
     */
    boolean isDisabled( Schema schema );

    /**
     * Tells if the SchemaManager is permissive or if it must be checked
     * against inconsistencies.
     *
     * @return True if SchemaObjects can be added even if they break the consistency
     */
    boolean isRelaxed();


    /**
     * Set the SchemaManager to a RELAXED mode
     */
    void setRelaxed();

    /**
     * Tells if the SchemaManager is strict.
     *
     * @return True if SchemaObjects cannot be added if they break the consistency
     */
    boolean isStrict();

    /**
     * Set the SchemaManager to a STRICT mode
     */
    void setStrict();
    
    /**
     * Check that the Schemas are consistent regarding the current Registries.
     * 
     * @param schemas The schemas to check
     * @return true if the schemas can be loaded in the registries
     * @throws LdapException if something went wrong
     */
    boolean verify( Schema... schemas ) throws LdapException;


    /**
     * Check that the Schemas are consistent regarding the current Registries.
     * 
     * @param schemas The schema names to check
     * @return true if the schemas can be loaded in the registries
     * @throws LdapException if something went wrong
     */
    boolean verify( String... schemas ) throws LdapException;


    /**
     * @return The Registries
     */
    Registries getRegistries();


    /**
     * Lookup for an AttributeType in the AttributeType registry
     * 
     * @param oid the OID we are looking for
     * @return The found AttributeType 
     * @throws LdapException if the OID is not found in the AttributeType registry
     */
    AttributeType lookupAttributeTypeRegistry( String oid ) throws LdapException;


    /**
     * Get an AttributeType in the AttributeType registry. This method won't
     * throw an exception if the AttributeTyp is not found, it will just return
     * null.
     * 
     * @param oid the OID we are looking for
     * @return The found AttributeType, or null if not found
     */
    AttributeType getAttributeType( String oid );


    /**
     * Lookup for a Comparator in the Comparator registry
     * 
     * @param oid the OID we are looking for
     * @return The found Comparator 
     * @throws LdapException if the OID is not found in the Comparator registry
     */
    LdapComparator<?> lookupComparatorRegistry( String oid ) throws LdapException;


    /**
     * Lookup for a MatchingRule in the MatchingRule registry
     * 
     * @param oid the OID we are looking for
     * @return The found MatchingRule 
     * @throws LdapException if the OID is not found in the MatchingRule registry
     */
    MatchingRule lookupMatchingRuleRegistry( String oid ) throws LdapException;


    /**
     * Lookup for a Normalizer in the Normalizer registry
     * 
     * @param oid the OID we are looking for
     * @return The found Normalizer 
     * @throws LdapException if the OID is not found in the Normalizer registry
     */
    Normalizer lookupNormalizerRegistry( String oid ) throws LdapException;


    /**
     * Lookup for a ObjectClass in the ObjectClass registry
     * 
     * @param oid the OID we are looking for
     * @return The found ObjectClass 
     * @throws LdapException if the OID is not found in the ObjectClass registry
     */
    ObjectClass lookupObjectClassRegistry( String oid ) throws LdapException;


    /**
     * Lookup for an LdapSyntax in the LdapSyntax registry
     * 
     * @param oid the OID we are looking for
     * @return The found LdapSyntax 
     * @throws LdapException if the OID is not found in the LdapSyntax registry
     */
    LdapSyntax lookupLdapSyntaxRegistry( String oid ) throws LdapException;


    /**
     * Lookup for a SyntaxChecker in the SyntaxChecker registry
     * 
     * @param oid the OID we are looking for
     * @return The found SyntaxChecker 
     * @throws LdapException if the OID is not found in the SyntaxChecker registry
     */
    SyntaxChecker lookupSyntaxCheckerRegistry( String oid ) throws LdapException;


    /**
     * Get an immutable reference on the AttributeType registry
     * 
     * @return A reference to the AttributeType registry.
     */
    AttributeTypeRegistry getAttributeTypeRegistry();


    /**
     * Get an immutable reference on the Comparator registry
     * 
     * @return A reference to the Comparator registry.
     */
    ComparatorRegistry getComparatorRegistry();


    /**
     * Get an immutable reference on the DitContentRule registry
     * 
     * @return A reference to the DitContentRule registry.
     */
    DitContentRuleRegistry getDITContentRuleRegistry();


    /**
     * Get an immutable reference on the DitStructureRule registry
     * 
     * @return A reference to the DitStructureRule registry.
     */
    DitStructureRuleRegistry getDITStructureRuleRegistry();


    /**
     * Get an immutable reference on the MatchingRule registry
     * 
     * @return A reference to the MatchingRule registry.
     */
    MatchingRuleRegistry getMatchingRuleRegistry();


    /**
     * Get an immutable reference on the MatchingRuleUse registry
     * 
     * @return A reference to the MatchingRuleUse registry.
     */
    MatchingRuleUseRegistry getMatchingRuleUseRegistry();


    /**
     * Get an immutable reference on the Normalizer registry
     * 
     * @return A reference to the Normalizer registry.
     */
    NormalizerRegistry getNormalizerRegistry();


    /**
     * Get an immutable reference on the NameForm registry
     * 
     * @return A reference to the NameForm registry.
     */
    NameFormRegistry getNameFormRegistry();


    /**
     * Get an immutable reference on the ObjectClass registry
     * 
     * @return A reference to the ObjectClass registry.
     */
    ObjectClassRegistry getObjectClassRegistry();


    /**
     * Get an immutable reference on the LdapSyntax registry
     * 
     * @return A reference to the LdapSyntax registry.
     */
    LdapSyntaxRegistry getLdapSyntaxRegistry();


    /**
     * Get an immutable reference on the SyntaxChecker registry
     * 
     * @return A reference to the SyntaxChecker registry.
     */
    SyntaxCheckerRegistry getSyntaxCheckerRegistry();


    /**
     * Get an immutable reference on the Normalizer mapping
     * 
     * @return A reference to the Normalizer mapping
     */
    Map<String, OidNormalizer> getNormalizerMapping();


    /**
     * Associate a new Registries to the SchemaManager
     *
     * @param registries The new Registries
     */
    void setRegistries( Registries registries );


    /**
     * @return The errors obtained when checking the registries
     */
    List<Throwable> getErrors();


    /**
     * @return the namingContext
     */
    Dn getNamingContext();


    /**
     * Initializes the SchemaService
     *
     * @throws LdapException If the initialization fails
     */
    void initialize() throws LdapException;


    /**
     * Registers a new SchemaObject. The registries will be updated only if it's
     * consistent after this addition, if the SchemaManager is in Strict mode.
     * If something went wrong during this operation, the 
     * SchemaManager.getErrors() will give the list of generated errors.
     *
     * @param schemaObject the SchemaObject to register
     * @return true if the addition has been made, false if there were some errors
     * @throws LdapException if the SchemaObject is already registered or
     * the registration operation is not supported
     */
    boolean add( SchemaObject schemaObject ) throws LdapException;
    
    
    /**
     * Add a new Schema into the SchemaManager.
     *
     * @param schema The schema to add
     * @return <tt>true</tt> if the Shcema has been correctly loaded, <tt>false</tt> if we had some errors 
     */
    //boolean add( Schema schema ) throws LdapException;
    
    
    /**
     * Add a new Schema from a file into the SchemaManager. We will use the default schemaLoader.
     *
     * @param schemaFile The file containing the schema to add
     * @return <tt>true</tt> if the Shcema has been correctly loaded, <tt>false</tt> if we had some errors 
     */
    //boolean add( String schemaFile ) throws LdapException;

    
    /**
     * Add a new Schema into the SchemaManager, using a new SchemaLoader.
     *
     * @param schemaFile The file containing the schema to add
     * @param schemaLoader The SchemaLoader to use to load this new schema
     * @return <tt>true</tt> if the Shcema has been correctly loaded, <tt>false</tt> if we had some errors 
     */
    //boolean add( String schemaFile, SchemaLoader schemaLoader ) throws LdapException;


    /**
     * Unregisters a new SchemaObject. The registries will be updated only if it's
     * consistent after this deletion, if the SchemaManager is in Strict mode.
     * If something went wrong during this operation, the 
     * SchemaManager.getErrors() will give the list of generated errors.
     *
     * @param schemaObject the SchemaObject to unregister
     * @return true if the deletion has been made, false if there were some errors
     * @throws LdapException if the SchemaObject is not registered or
     * the deletion operation is not supported
     */
    boolean delete( SchemaObject schemaObject ) throws LdapException;


    /**
     * Removes the registered attributeType from the attributeTypeRegistry 
     * 
     * @param attributeTypeOid the attributeType OID to unregister
     * @throws LdapException if the attributeType is invalid
     * @return the unregistred AtttributeType
     */
    SchemaObject unregisterAttributeType( String attributeTypeOid ) throws LdapException;


    /**
     * Removes the registered Comparator from the ComparatorRegistry 
     * 
     * @param comparatorOid the Comparator OID to unregister
     * @throws LdapException if the Comparator is invalid
     * @return the unregistred Comparator
     */
    SchemaObject unregisterComparator( String comparatorOid ) throws LdapException;


    /**
     * Removes the registered DitControlRule from the DitControlRuleRegistry 
     * 
     * @param ditControlRuleOid the DitControlRule OID to unregister
     * @throws LdapException if the DitControlRule is invalid
     * @return the unregistred DitControlRule
     */
    SchemaObject unregisterDitControlRule( String ditControlRuleOid ) throws LdapException;


    /**
     * Removes the registered DitStructureRule from the DitStructureRuleRegistry 
     * 
     * @param ditStructureRuleOid the DitStructureRule OID to unregister
     * @throws LdapException if the DitStructureRule is invalid
     * @return the unregistred DitStructureRule
     */
    SchemaObject unregisterDitStructureRule( String ditStructureRuleOid ) throws LdapException;


    /**
     * Removes the registered MatchingRule from the MatchingRuleRegistry 
     * 
     * @param matchingRuleOid the MatchingRuleRule OID to unregister
     * @throws LdapException if the MatchingRule is invalid
     * @return the unregistred MatchingRule
     */
    SchemaObject unregisterMatchingRule( String matchingRuleOid ) throws LdapException;


    /**
     * Removes the registered MatchingRuleUse from the MatchingRuleUseRegistry 
     * 
     * @param matchingRuleUseOid the MatchingRuleUse OID to unregister
     * @throws LdapException if the MatchingRuleUse is invalid
     * @return the unregistred MatchingRuleUse
     */
    SchemaObject unregisterMatchingRuleUse( String matchingRuleUseOid ) throws LdapException;


    /**
     * Removes the registered NameForm from the NameFormRegistry 
     * 
     * @param nameFormOid the NameForm OID to unregister
     * @throws LdapException if the NameForm is invalid
     * @return the unregistred NameForm
     */
    SchemaObject unregisterNameForm( String nameFormOid ) throws LdapException;


    /**
     * Removes the registered Normalizer from the NormalizerRegistry 
     * 
     * @param normalizerOid the Normalizer OID to unregister
     * @throws LdapException if the Normalizer is invalid
     * @return the unregistred Normalizer
     */
    SchemaObject unregisterNormalizer( String normalizerOid ) throws LdapException;


    /**
     * Removes the registered ObjectClass from the ObjectClassRegistry 
     * 
     * @param objectClassOid the ObjectClass OID to unregister
     * @throws LdapException if the ObjectClass is invalid
     * @return the unregistred ObjectClass
     */
    SchemaObject unregisterObjectClass( String objectClassOid ) throws LdapException;


    /**
     * Removes the registered LdapSyntax from the LdapSyntaxRegistry 
     * 
     * @param ldapSyntaxOid the LdapSyntax OID to unregister
     * @throws LdapException if the LdapSyntax is invalid
     * @return the unregistred Syntax
     */
    SchemaObject unregisterLdapSyntax( String ldapSyntaxOid ) throws LdapException;


    /**
     * Removes the registered SyntaxChecker from the SyntaxCheckerRegistry 
     * 
     * @param syntaxCheckerOid the SyntaxChecker OID to unregister
     * @throws LdapException if the SyntaxChecker is invalid
     * @return the unregistred SyntaxChecker
     */
    SchemaObject unregisterSyntaxChecker( String syntaxCheckerOid ) throws LdapException;


    /**
     * Returns a reference to the global OidRegistry
     *
     * @return The the global OidRegistry
     */
    @SuppressWarnings("rawtypes")
    OidRegistry getGlobalOidRegistry();


    /**
     * Gets a schema that has been loaded into these Registries.
     * 
     * @param schemaName the name of the schema to lookup
     * @return the loaded Schema if one corresponding to the name exists
     */
    Schema getLoadedSchema( String schemaName );


    /**
     * Tells if the specific schema is loaded
     *
     * @param schemaName The schema we want to check
     * @return true if the schema is laoded
     */
    boolean isSchemaLoaded( String schemaName );


    /**
     * Get the list of Schema names which has the given schema name as a dependence
     *
     * @param schemaName The Schema name for which we want to get the list of dependent schemas
     * @return The list of dependent schemas
     */
    Set<String> listDependentSchemaNames( String schemaName );
}
