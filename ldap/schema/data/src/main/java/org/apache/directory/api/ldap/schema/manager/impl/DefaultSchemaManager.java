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
package org.apache.directory.api.ldap.schema.manager.impl;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.exception.LdapProtocolErrorException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaExceptionCodes;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.LoadableSchemaObject;
import org.apache.directory.api.ldap.model.schema.LoggingSchemaErrorHandler;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaErrorHandler;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObjectWrapper;
import org.apache.directory.api.ldap.model.schema.SchemaUtils;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.normalizers.OidNormalizer;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ComparatorRegistry;
import org.apache.directory.api.ldap.model.schema.registries.DitContentRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.DitStructureRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableAttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableComparatorRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableDitContentRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableDitStructureRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableLdapSyntaxRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableMatchingRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableMatchingRuleUseRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableNameFormRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableNormalizerRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ImmutableSyntaxCheckerRegistry;
import org.apache.directory.api.ldap.model.schema.registries.LdapSyntaxRegistry;
import org.apache.directory.api.ldap.model.schema.registries.LowerCaseKeyMap;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleUseRegistry;
import org.apache.directory.api.ldap.model.schema.registries.NameFormRegistry;
import org.apache.directory.api.ldap.model.schema.registries.NormalizerRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.OidRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.model.schema.registries.SyntaxCheckerRegistry;
import org.apache.directory.api.ldap.schema.loader.EntityFactory;
import org.apache.directory.api.ldap.schema.loader.JarLdifSchemaLoader;
import org.apache.directory.api.ldap.schema.loader.SchemaEntityFactory;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The SchemaManager class : it handles all the schema operations (addition, removal,
 * modification).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultSchemaManager implements SchemaManager
{
    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultSchemaManager.class );

    /** The NamingContext this SchemaManager is associated with */
    private Dn namingContext;

    /** The global registries for this namingContext */
    private volatile Registries registries;

    /** the factory that generates respective SchemaObjects from LDIF entries */
    private final EntityFactory factory;

    /** A Map containing all the schema being dependent from a schema */
    private Map<String, Set<String>> schemaDependencies = new HashMap<>();
    
    /**
     * A map of all available schema names to schema objects. This map is
     * populated when this class is created with all the schemas present in
     * the LDIF based schema repository.
     */
    private Map<String, Schema> schemaMap = new LowerCaseKeyMap();

    /** A flag indicating that the SchemaManager is relaxed or not */
    private boolean isRelaxed = STRICT;
    
    /**
     * Class that handles all the error that may occur during schema processing.
     */
    private SchemaErrorHandler errorHandler;

    /**
     * Creates a new instance of DefaultSchemaManager with the default schema schemaLoader
     */
    public DefaultSchemaManager()
    {
        // Default to the the root (one schemaManager for all the entries
        namingContext = Dn.ROOT_DSE;
        registries = new Registries();
        factory = new SchemaEntityFactory();
        isRelaxed = STRICT;
        setErrorHandler( new LoggingSchemaErrorHandler() );
        
        try
        {
            SchemaLoader schemaLoader = new JarLdifSchemaLoader();
            
            for ( Schema schema : schemaLoader.getAllSchemas() )
            {
                schemaMap.put( schema.getSchemaName(), schema );
            }
            
            loadAllEnabled();
        }
        catch ( LdapException | IOException e )
        {
            LOG.error( I18n.err( I18n.ERR_16077_SCHEMA_MANAGER_CANT_BE_LOADED, e.getMessage() ) );
            throw new RuntimeException( e.getMessage() );
        }
    }

    
    /**
     * Creates a new instance of DefaultSchemaManager with the default schema schemaLoader
     * 
     * @param schemas The list of schema to load
     */
    public DefaultSchemaManager( Collection<Schema> schemas )
    {
        // Default to the the root (one schemaManager for all the entries
        namingContext = Dn.ROOT_DSE;
        
        for ( Schema schema : schemas )
        {
            schemaMap.put( schema.getSchemaName(), schema );
        }
        
        registries = new Registries();
        factory = new SchemaEntityFactory();
        isRelaxed = STRICT;
        setErrorHandler( new LoggingSchemaErrorHandler() );
    }

    
    /**
     * Creates a new instance of DefaultSchemaManager with the default schema schemaLoader
     * 
     * @param schemaLoader The schemaLoader containing the schemas to load
     */
    public DefaultSchemaManager( SchemaLoader schemaLoader )
    {
        // Default to the the root (one schemaManager for all the entries
        namingContext = Dn.ROOT_DSE;
        
        for ( Schema schema : schemaLoader.getAllSchemas() )
        {
            schemaMap.put( schema.getSchemaName(), schema );
        }
        
        registries = new Registries();
        factory = new SchemaEntityFactory();
        isRelaxed = STRICT;
        setErrorHandler( new LoggingSchemaErrorHandler() );
    }
    

    /**
     * Creates a new instance of DefaultSchemaManager with the default schema schemaLoader
     *
     * @param relaxed If the schema  manager should be relaxed or not
     * @param schemas The list of schema to load
     */
    public DefaultSchemaManager( boolean relaxed, Collection<Schema> schemas )
    {
        // Default to the the root (one schemaManager for all the entries
        namingContext = Dn.ROOT_DSE;

        for ( Schema schema : schemas )
        {
            schemaMap.put( schema.getSchemaName(), schema );
        }
        
        registries = new Registries();
        factory = new SchemaEntityFactory();
        isRelaxed = relaxed;
        setErrorHandler( new LoggingSchemaErrorHandler() );
    }


    //-----------------------------------------------------------------------
    // Helper methods
    //-----------------------------------------------------------------------
    /**
     * Clone the registries before doing any modification on it. Relax it
     * too so that we can update it.
     * 
     * @return The cloned Registries
     * @throws LdapException If the Registries cannot be cloned
     */
    private Registries cloneRegistries() throws LdapException
    {
        try
        {
            // Relax the controls at first

            // Clone the Registries
            Registries clonedRegistries = registries.clone();

            // And update references. We may have errors, that may be fixed
            // by the new loaded schemas.
            clonedRegistries.checkRefInteg();

            // Now, relax the cloned Registries if there is no error
            clonedRegistries.setRelaxed();

            return clonedRegistries;
        }
        catch ( CloneNotSupportedException cnse )
        {
            throw new LdapOtherException( cnse.getMessage(), cnse );
        }
    }


    /**
     * Transform a String[] array of schema to a Schema[]
     * 
     * @param schemas The Schema names to process
     * @return an array of Schema instance
     * @throws LdapException If one of the Schema cannot be found
     */
    private Schema[] toArray( String... schemas ) throws LdapException
    {
        Schema[] schemaArray = new Schema[schemas.length];
        int n = 0;

        for ( String schemaName : schemas )
        {
            Schema schema = schemaMap.get( schemaName );

            if ( schema != null )
            {
                schemaArray[n++] = schema;
            }
            else
            {
                throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, I18n.err(
                    I18n.ERR_16078_CANNOT_LOAD_UNKNOWN_SCHEMA, schemaName ) );
            }
        }

        return schemaArray;
    }


    private void addSchemaObjects( Schema schema, Registries registries ) throws LdapException
    {
        // Create a content container for this schema
        registries.addSchema( schema.getSchemaName() );
        schemaMap.put( schema.getSchemaName(), schema );

        // And inject any existing SchemaObject into the registries
        try
        {
            addComparators( schema, registries );
            addNormalizers( schema, registries );
            addSyntaxCheckers( schema, registries );
            addSyntaxes( schema, registries );
            addMatchingRules( schema, registries );
            addAttributeTypes( schema, registries );
            addObjectClasses( schema, registries );
            //addMatchingRuleUses( schema, registries );
            //addDitContentRules( schema, registries );
            //addNameForms( schema, registries );
            //addDitStructureRules( schema, registries );
        }
        catch ( IOException ioe )
        {
            throw new LdapOtherException( ioe.getMessage(), ioe );
        }
    }


    /**
     * Delete all the schemaObjects for a given schema from the registries
     * 
     * @param schema The schema from which we want teh SchemaObjects to be deleted
     * @param registries The Registries to process
     * @throws LdapException If the SchemaObjects cannot be deleted
     */
    private void deleteSchemaObjects( Schema schema, Registries registries ) throws LdapException
    {
        Map<String, Set<SchemaObjectWrapper>> schemaObjects = registries.getObjectBySchemaName();
        Set<SchemaObjectWrapper> content = schemaObjects.get( Strings.toLowerCaseAscii( schema.getSchemaName() ) );

        List<SchemaObject> toBeDeleted = new ArrayList<>();

        if ( content != null )
        {
            // Build an intermediate list to avoid concurrent modifications
            for ( SchemaObjectWrapper schemaObjectWrapper : content )
            {
                toBeDeleted.add( schemaObjectWrapper.get() );
            }

            for ( SchemaObject schemaObject : toBeDeleted )
            {
                registries.delete( schemaObject );
            }
        }
    }


    //-----------------------------------------------------------------------
    // API methods
    //-----------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean disable( Schema... schemas ) throws LdapException
    {
        boolean disabled = false;

        // Reset the error handler
        errorHandler.reset();

        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();
        clonedRegistries.setRelaxed();
        
        for ( Schema schema : schemas )
        {
            unload( clonedRegistries, schema );
        }
        
        // Unload is producing some errors, not sure why. But they
        // seem not relevant to disable functionality.
        errorHandler.reset();
        
        // Build the cross references
        clonedRegistries.buildReferences();

        // Destroy the clonedRegistry
        clonedRegistries.clear();

        if ( !errorHandler.wasError() )
        {
            // Ok no errors. Check the registries now
            clonedRegistries.checkRefInteg();
            
            if ( !errorHandler.wasError() )
            {
                // We are golden : let's apply the schemas in the real registries
                for ( Schema schema : schemas )
                {
                    unload( registries, schema );
                    schema.disable();
                }
                
                // Unload is producing some errors, not sure why. But they
                // seem not relevant to disable functionality.
                errorHandler.reset();

                // Build the cross references
                registries.buildReferences();
                registries.setStrict();

                disabled = true;
            }
        }

        // clear the cloned registries
        clonedRegistries.clear();

        return disabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean disable( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = toArray( schemaNames );

        return disable( schemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean disabledRelaxed( Schema... schemas )
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean disabledRelaxed( String... schemas )
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Schema> getDisabled()
    {
        List<Schema> disabled = new ArrayList<>();

        for ( Schema schema : registries.getLoadedSchemas().values() )
        {
            if ( schema.isDisabled() )
            {
                disabled.add( schema );
            }
        }

        return disabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean enable( Schema... schemas ) throws LdapException
    {
        boolean enabled = false;

        // Reset the errors if not null
        errorHandler.reset();

        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();
        clonedRegistries.setRelaxed();

        Set<Schema> disabledSchemas = new HashSet<>();

        for ( Schema schema : schemas )
        {
            if ( schema.getDependencies() != null )
            {
                for ( String dependency : schema.getDependencies() )
                {
                    Schema dependencySchema = schemaMap.get( dependency );

                    if ( dependencySchema.isDisabled() )
                    {
                        disabledSchemas.add( dependencySchema );
                    }
                }
            }

            schema.enable();
            load( clonedRegistries, schema );
        }

        // Revert back the disabled schema to disabled
        for ( Schema disabledSchema : disabledSchemas )
        {
            if ( disabledSchema.isEnabled() )
            {
                disabledSchema.disable();
            }
        }

        // Build the cross references
        clonedRegistries.buildReferences();

        // Destroy the clonedRegistry
        clonedRegistries.clear();

        if ( !errorHandler.wasError() )
        {
            // Ok no errors. Check the registries now
            clonedRegistries.checkRefInteg();

            if ( !errorHandler.wasError() )
            {
                // We are golden : let's apply the schemas in the real registries
                for ( Schema schema : schemas )
                {
                    schema.enable();
                    load( registries, schema );
                }

                // Build the cross references
                registries.buildReferences();
                registries.setStrict();

                enabled = true;
            }
        }

        // clear the cloned registries
        clonedRegistries.clear();

        return enabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean enable( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = toArray( schemaNames );
        return enable( schemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean enableRelaxed( Schema... schemas )
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean enableRelaxed( String... schemas )
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Schema> getEnabled()
    {
        List<Schema> enabled = new ArrayList<>();

        for ( Schema schema : registries.getLoadedSchemas().values() )
        {
            if ( schema.isEnabled() )
            {
                enabled.add( schema );
            }
        }

        return enabled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Schema> getAllSchemas()
    {
        List<Schema> schemas = new ArrayList<>();

        for ( Schema schema : schemaMap.values() )
        {
            if ( schema.isEnabled() )
            {
                schemas.add( schema );
            }
        }

        return schemas;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Throwable> getErrors()
    {
        return errorHandler.getErrors();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Registries getRegistries()
    {
        return registries;
    }


    /**
     * Currently not implemented.
     * 
     * @return Always FALSE
     */
    public boolean isDisabledAccepted()
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean load( Schema... schemas ) throws LdapException
    {
        if ( schemas.length == 0 )
        {
            return true;
        }

        boolean loaded = false;

        // Reset the errors if not null
        errorHandler.reset();

        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();
        clonedRegistries.setRelaxed();

        // Load the schemas
        for ( Schema schema : schemas )
        {
            boolean singleSchemaLoaded = load( clonedRegistries, schema );

            // return false if the schema was not loaded in the first place
            if ( !singleSchemaLoaded )
            {
                return false;
            }
        }

        // Build the cross references
        clonedRegistries.buildReferences();

        if ( !errorHandler.wasError() )
        {
            // Ok no errors. Check the registries now
            clonedRegistries.checkRefInteg();

            if ( !errorHandler.wasError() )
            {
                // We are golden : let's apply the schema in the real registries
                registries.setRelaxed();

                // Load the schemas
                for ( Schema schema : schemas )
                {
                    load( registries, schema );

                    // Update the schema dependences if needed
                    if ( schema.getDependencies() != null )
                    {
                        for ( String dep : schema.getDependencies() )
                        {
                            Set<String> deps = schemaDependencies.get( dep );

                            if ( deps == null )
                            {
                                deps = new HashSet<>();
                                deps.add( schema.getSchemaName() );
                            }

                            // Replace the dependences
                            schemaDependencies.put( dep, deps );
                        }
                    }

                    // add the schema to the SchemaMap
                    schemaMap.put( schema.getSchemaName(), schema );
                }

                // Build the cross references
                registries.buildReferences();
                registries.setStrict();

                loaded = true;
            }
        }

        // clear the cloned registries
        clonedRegistries.clear();

        return loaded;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean load( String... schemaNames ) throws LdapException
    {
        if ( schemaNames.length == 0 )
        {
            return true;
        }

        Schema[] schemas = toArray( schemaNames );

        return load( schemas );
    }


    /**
     * Load the schema in the registries. We will load everything accordingly to the two flags :
     * - isRelaxed
     * - disabledAccepted
     * 
     * @param registries The Registries to process
     * @param schema The schema to load in the Registries
     * @return <tt>true</tt> if the schema has been loaded
     * @throws LdapException If the schema cannot be loaded
     */
    private boolean load( Registries registries, Schema schema ) throws LdapException
    {
        if ( schema == null )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16013_SCHEMA_IS_NULL ) );
            }
            
            return false;
        }

        // First avoid loading twice the same schema
        if ( registries.isSchemaLoaded( schema.getSchemaName() ) )
        {
            return true;
        }

        if ( schema.isDisabled() )
        {
            if ( registries.isDisabledAccepted() )
            {
                if ( LOG.isInfoEnabled() )
                {
                    LOG.info( I18n.msg( I18n.MSG_16014_LOADING_DISABLED_SCHEMA, schema.getSchemaName(), schema ) );
                }

                registries.schemaLoaded( schema );
                addSchemaObjects( schema, registries );
            }
            else
            {
                return false;
            }
        }
        else
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16015_LOADING_ENABLED_SCHEMA, schema.getSchemaName(), schema ) );
            }

            // Check that the dependencies, if any, are correct
            if ( schema.getDependencies() != null )
            {
                for ( String dependency : schema.getDependencies() )
                {
                    Schema dependencySchema = schemaMap.get( dependency );

                    if ( dependencySchema == null )
                    {
                        // The dependency has not been loaded.
                        String msg = I18n.err( I18n.ERR_16035_CANNOT_LOAD_SCHEMA, schema.getSchemaName() );
                        
                        if ( LOG.isInfoEnabled() )
                        {
                            LOG.info( msg );
                        }
                        
                        LdapProtocolErrorException error = new LdapProtocolErrorException( msg );
                        errorHandler.handle( LOG, msg, error );

                        return false;
                    }

                    // If the dependency is disabled, then enable it
                    if ( dependencySchema.isDisabled() )
                    {
                        dependencySchema.enable();

                        if ( !load( registries, dependencySchema ) )
                        {
                            dependencySchema.disable();

                            return false;
                        }
                    }
                }
            }

            registries.schemaLoaded( schema );
            addSchemaObjects( schema, registries );
        }

        return true;
    }


    /**
     * Unload the schema from the registries. We will unload everything accordingly to the two flags :
     * - isRelaxed
     * - disabledAccepted
     * 
     * @param registries The Registries to process
     * @param schema The schema to unload from the Registries
     * @return <tt>true</tt> if the schema has been unloaded
     * @throws LdapException If the schema cannot be unloaded
     */
    private boolean unload( Registries registries, Schema schema ) throws LdapException
    {
        if ( schema == null )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16013_SCHEMA_IS_NULL )  );
            }
            
            return false;
        }

        // First avoid unloading twice the same schema
        if ( !registries.isSchemaLoaded( schema.getSchemaName() ) )
        {
            return true;
        }

        if ( schema.isEnabled() )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16016_UNLOADING_SCHEMA, schema.getSchemaName(), schema ) );
            }

            deleteSchemaObjects( schema, registries );
            registries.schemaUnloaded( schema );
        }

        return true;
    }


    /**
     * Add all the Schema's AttributeTypes
     * 
     * @param schema The schema in which the AttributeTypes will be added
     * @param registries The Registries to process
     * @throws LdapException If the AttributeTypes cannot be added
     * @throws IOException If the AttributeTypes cannot be loaded
     */
    private void addAttributeTypes( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadAttributeTypes( schema ) )
        {
            AttributeType attributeType = factory.getAttributeType( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, attributeType, schema );
        }
    }


    /**
     * Add all the Schema's comparators
     * 
     * @param schema The schema in which the Comparators will be added
     * @param registries The Registries to process
     * @throws LdapException If the Comparators cannot be added
     * @throws IOException If the Comparators cannot be loaded
     */
    private void addComparators( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }
        
        for ( Entry entry : schema.getSchemaLoader().loadComparators( schema ) )
        {
            LdapComparator<?> comparator = factory.getLdapComparator( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, comparator, schema );
        }
    }


    /**
     * Add all the Schema's DitContentRules
     */
    // Not yet implemented, but may be used
    //    @SuppressWarnings("PMD.UnusedFormalParameter")
    //    private void addDitContentRules( Schema schema, Registries registries ) throws LdapException, IOException
    //    {
    //        if ( !schema.getSchemaLoader().loadDitContentRules( schema ).isEmpty() )
    //        {
    //            throw new NotImplementedException( I18n.err( I18n.ERR_11003 ) );
    //        }
    //    }

    /**
     * Add all the Schema's DitStructureRules
     */
    // Not yet implemented, but may be used
    //    @SuppressWarnings("PMD.UnusedFormalParameter")
    //    private void addDitStructureRules( Schema schema, Registries registries ) throws LdapException, IOException
    //    {
    //        if ( !schema.getSchemaLoader().loadDitStructureRules( schema ).isEmpty() )
    //        {
    //            throw new NotImplementedException( I18n.err( I18n.ERR_11004 ) );
    //        }
    //    }

    /**
     * Add all the Schema's MatchingRules
     * 
     * @param schema The schema in which the MatchingRules will be added
     * @param registries The Registries to process
     * @throws LdapException If the MatchingRules cannot be added
     * @throws IOException If the MatchingRules cannot be loaded
     */
    private void addMatchingRules( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadMatchingRules( schema ) )
        {
            MatchingRule matchingRule = factory.getMatchingRule( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, matchingRule, schema );
        }
    }


    /**
     * Add all the Schema's MatchingRuleUses
     */
    // Not yet implemented, but may be used
    //    @SuppressWarnings("PMD.UnusedFormalParameter")
    //    private void addMatchingRuleUses( Schema schema, Registries registries ) throws LdapException, IOException
    //    {
    //        if ( !schema.getSchemaLoader().loadMatchingRuleUses( schema ).isEmpty() )
    //        {
    //            throw new NotImplementedException( I18n.err( I18n.ERR_11005 ) );
    //        }
    //        // for ( Entry entry : schema.getSchemaLoader().loadMatchingRuleUses( schema ) )
    //        // {
    //        //     throw new NotImplementedException( I18n.err( I18n.ERR_11005 ) );
    //        // }
    //    }

    /**
     * Add all the Schema's NameForms
     */
    // Not yet implemented, but may be used
    //    @SuppressWarnings("PMD.UnusedFormalParameter")
    //    private void addNameForms( Schema schema, Registries registries ) throws LdapException, IOException
    //    {
    //        if ( !schema.getSchemaLoader().loadNameForms( schema ).isEmpty() )
    //        {
    //            throw new NotImplementedException( I18n.err( I18n.ERR_11006 ) );
    //        }
    //    }

    /**
     * Add all the Schema's Normalizers
     * 
     * @param schema The schema in which the Normalizers will be added
     * @param registries The Registries to process
     * @throws LdapException If the Normalizers cannot be added
     * @throws IOException If the Normalizers cannot be loaded
     */
    private void addNormalizers( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadNormalizers( schema ) )
        {
            Normalizer normalizer = factory.getNormalizer( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, normalizer, schema );
        }
    }


    /**
     * Add all the Schema's ObjectClasses
     * 
     * @param schema The schema in which the ObjectClasses will be added
     * @param registries The Registries to process
     * @throws LdapException If the ObjectClasses cannot be added
     * @throws IOException If the ObjectClasses cannot be loaded
     */
    private void addObjectClasses( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadObjectClasses( schema ) )
        {
            ObjectClass objectClass = factory.getObjectClass( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, objectClass, schema );
        }
    }


    /**
     * Add all the Schema's Syntaxes
     * 
     * @param schema The schema in which the Syntaxes will be added
     * @param registries The Registries to process
     * @throws LdapException If the Syntaxes cannot be added
     * @throws IOException If the Syntaxes cannot be loaded
     */
    private void addSyntaxes( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadSyntaxes( schema ) )
        {
            LdapSyntax syntax = factory.getSyntax( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, syntax, schema );
        }
    }


    /**
     * Register all the Schema's SyntaxCheckers
     * 
     * @param schema The schema in which the SyntaxChecker will be added
     * @param registries The Registries to process
     * @throws LdapException If the SyntaxChecker cannot be added
     * @throws IOException If the SyntaxChecker cannot be loaded
     */
    private void addSyntaxCheckers( Schema schema, Registries registries ) throws LdapException, IOException
    {
        if ( schema.getSchemaLoader() == null )
        {
            return;
        }

        for ( Entry entry : schema.getSchemaLoader().loadSyntaxCheckers( schema ) )
        {
            SyntaxChecker syntaxChecker = factory.getSyntaxChecker( this, entry, registries, schema.getSchemaName() );

            addSchemaObject( registries, syntaxChecker, schema );
        }
    }


    /**
     * Add the schemaObject into the registries.
     *
     * @param registries The Registries
     * @param schemaObject The SchemaObject containing the SchemaObject description
     * @param schema The associated schema
     * @return the created schemaObject instance
     * @throws LdapException If the registering failed
     */
    private SchemaObject addSchemaObject( Registries registries, SchemaObject schemaObject, Schema schema )
        throws LdapException
    {
        if ( registries.isRelaxed() )
        {
            if ( registries.isDisabledAccepted() || ( schema.isEnabled() && schemaObject.isEnabled() ) )
            {
                registries.add( schemaObject, false );
            }
            else
            {
                // What kind of error is this? TODO: better message
                errorHandler.handle( LOG, null, new Throwable() );
            }
        }
        else
        {
            if ( schema.isEnabled() && schemaObject.isEnabled() )
            {
                registries.add( schemaObject, false );
            }
            else
            {
                // What kind of error is this? TODO: better message
                errorHandler.handle( LOG, null, new Throwable() );
            }
        }

        return schemaObject;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadAllEnabled() throws LdapException
    {
        Schema[] schemas = new Schema[schemaMap.size()];
        int i = 0;
        
        for ( Schema schema : schemaMap.values() )
        {
            if ( schema.isEnabled() )
            {
                schemas[i++] = schema;
            }
        }
        
        Schema[] enabledSchemas = new Schema[i];
        System.arraycopy( schemas, 0, enabledSchemas, 0, i );
        
        return loadWithDeps( enabledSchemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadAllEnabledRelaxed() throws LdapException
    {
        Schema[] enabledSchemas = new Schema[schemaMap.size()];
        int i = 0;
        
        for ( Schema schema : schemaMap.values() )
        {
            if ( schema.isEnabled() )
            {
                enabledSchemas[i++] = schema;
            }
        }
        
        return loadWithDepsRelaxed( enabledSchemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadDisabled( Schema... schemas ) throws LdapException
    {
        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();

        // Accept the disabled schemas
        clonedRegistries.setDisabledAccepted( true );

        // Load the schemas
        for ( Schema schema : schemas )
        {
            // Enable the Schema object before loading it
            schema.enable();
            load( clonedRegistries, schema );
        }

        clonedRegistries.clear();

        // Apply the change to the correct registries if no errors
        if ( !errorHandler.wasError() )
        {
            // No error, we can enable the schema in the real registries
            for ( Schema schema : schemas )
            {
                load( registries, schema );
            }

            return true;
        }
        else
        {
            for ( Schema schema : schemas )
            {
                schema.disable();
            }

            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadDisabled( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = toArray( schemaNames );

        return loadDisabled( schemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadRelaxed( Schema... schemas ) throws LdapException
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadRelaxed( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = toArray( schemaNames );
        return loadRelaxed( schemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadWithDeps( Schema... schemas ) throws LdapException
    {
        boolean loaded = false;

        // Reset the errors if not null
        errorHandler.reset();

        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();
        clonedRegistries.setRelaxed();

        // Load the schemas
        for ( Schema schema : schemas )
        {
            loadDepsFirst( clonedRegistries, schema );
        }

        // Build the cross references
        clonedRegistries.buildReferences();

        if ( !errorHandler.wasError() )
        {
            // Ok no errors. Check the registries now
            clonedRegistries.checkRefInteg();

            if ( !errorHandler.wasError() )
            {
                // We are golden : let's apply the schema in the real registries
                registries = clonedRegistries;
                registries.setStrict();
                loaded = true;
            }
        }
        else if ( isStrict() )
        {
            // clear the cloned registries
            clonedRegistries.clear();
        }
        else
        {
            // Relaxed mode
            registries = clonedRegistries;
            registries.setRelaxed();
            loaded = true;
        }

        return loaded;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadWithDeps( String... schemas ) throws LdapException
    {
        return loadWithDeps( toArray( schemas ) );
    }


    /**
     * Recursive method which loads schema's with their dependent schemas first
     * and tracks what schemas it has seen so the recursion does not go out of
     * control with dependency cycle detection.
     *
     * @param registries The Registries in which the schemas will be loaded
     * @param schema the current schema we are attempting to load
     * @throws LdapException if there is a cycle detected and/or another
     * failure results while loading, producing and or registering schema objects
     */
    private void loadDepsFirst( Registries registries, Schema schema ) throws LdapException
    {
        if ( schema == null )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16013_SCHEMA_IS_NULL )  );
            }
            
            return;
        }

        if ( schema.isDisabled() && !registries.isDisabledAccepted() )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16017_UNACCEPTED_DISABLED_SCHEMA ) );
            }
            
            return;
        }

        String schemaName = schema.getSchemaName();

        if ( registries.isSchemaLoaded( schemaName ) )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16018_SCHEMA_ALREADY_LOADED, schema.getSchemaName() ) );
            }
            
            return;
        }

        String[] deps = schema.getDependencies();

        // if no deps then load this guy and return
        if ( ( deps == null ) || ( deps.length == 0 ) )
        {
            load( registries, schema );

            return;
        }

        /*
         * We got deps and need to load them before this schema.  We go through
         * all deps loading them with their deps first if they have not been
         * loaded.
         */
        for ( String depName : deps )
        {
            if ( !registries.isSchemaLoaded( depName ) )
            {
                // Call recursively this method
                Schema schemaDep = schemaMap.get( depName );
                loadDepsFirst( registries, schemaDep );
            }
        }

        // Now load the current schema
        load( registries, schema );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadWithDepsRelaxed( Schema... schemas ) throws LdapException
    {
        registries.setRelaxed();

        // Load the schemas
        for ( Schema schema : schemas )
        {
            loadDepsFirstRelaxed( schema );
        }

        // Build the cross references
        registries.buildReferences();

        // Check the registries now
        registries.checkRefInteg();

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean loadWithDepsRelaxed( String... schemas ) throws LdapException
    {
        return loadWithDepsRelaxed( toArray( schemas ) );
    }


    /**
     * Recursive method which loads schema's with their dependent schemas first
     * and tracks what schemas it has seen so the recursion does not go out of
     * control with dependency cycle detection.
     *
     * @param schema the current schema we are attempting to load
     * @throws LdapException if there is a cycle detected and/or another
     * failure results while loading, producing and or registering schema objects
     */
    private void loadDepsFirstRelaxed( Schema schema ) throws LdapException
    {
        if ( schema == null )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16013_SCHEMA_IS_NULL )  );
            }
            
            return;
        }

        if ( schema.isDisabled() && !registries.isDisabledAccepted() )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16017_UNACCEPTED_DISABLED_SCHEMA ) );
            }
            
            return;
        }

        String schemaName = schema.getSchemaName();

        if ( registries.isSchemaLoaded( schemaName ) )
        {
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.msg( I18n.MSG_16018_SCHEMA_ALREADY_LOADED, schema.getSchemaName() ) );
            }
            
            return;
        }

        String[] deps = schema.getDependencies();

        // if no deps then load this guy and return
        if ( ( deps == null ) || ( deps.length == 0 ) )
        {
            load( registries, schema );

            return;
        }

        /*
         * We got deps and need to load them before this schema.  We go through
         * all deps loading them with their deps first if they have not been
         * loaded.
         */
        for ( String depName : deps )
        {
            if ( !registries.isSchemaLoaded( schemaName ) )
            {
                // Call recursively this method
                Schema schemaDep = schema.getSchemaLoader().getSchema( depName );
                loadDepsFirstRelaxed( schemaDep );
            }
        }

        // Now load the current schema
        load( registries, schema );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRegistries( Registries registries )
    {
        this.registries = registries;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean unload( Schema... schemas ) throws LdapException
    {
        boolean unloaded = false;

        // Reset the errors if not null
        errorHandler.reset();

        // Work on a cloned and relaxed registries
        Registries clonedRegistries = cloneRegistries();
        clonedRegistries.setRelaxed();

        // Load the schemas
        for ( Schema schema : schemas )
        {
            unload( clonedRegistries, schema );
        }

        // Build the cross references
        clonedRegistries.buildReferences();

        if ( !errorHandler.wasError() )
        {
            // Ok no errors. Check the registries now
            clonedRegistries.checkRefInteg();

            if ( !errorHandler.wasError() )
            {
                // We are golden : let's apply the schema in the real registries
                registries.setRelaxed();

                // Load the schemas
                for ( Schema schema : schemas )
                {
                    unload( registries, schema );

                    // Update the schema dependences
                    for ( String dep : schema.getDependencies() )
                    {
                        Set<String> deps = schemaDependencies.get( dep );

                        if ( deps != null )
                        {
                            deps.remove( schema.getSchemaName() );
                        }
                    }

                    schemaMap.remove( schema.getSchemaName() );
                }

                // Build the cross references
                registries.buildReferences();
                registries.setStrict();

                unloaded = true;
            }
        }

        // clear the cloned registries
        clonedRegistries.clear();

        return unloaded;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean unload( String... schemaNames ) throws LdapException
    {
        Schema[] schemas = toArray( schemaNames );

        return unload( schemas );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify( Schema... schemas ) throws LdapException
    {
        errorHandler.reset();
        // Work on a cloned registries
        Registries clonedRegistries = cloneRegistries();

        // Loop on all the schemas
        for ( Schema schema : schemas )
        {
            try
            {
                // Inject the schema
                boolean loaded = load( clonedRegistries, schema );

                if ( !loaded )
                {
                    // We got an error : exit
                    clonedRegistries.clear();
                    return false;
                }

                // Now, check the registries
                clonedRegistries.checkRefInteg();

                if ( !errorHandler.wasError() )
                {
                    // We got an error : exit
                    clonedRegistries.clear();
                    return false;
                }
            }
            catch ( Exception e )
            {
                // We got an error : exit
                clonedRegistries.clear();
                return false;
            }
        }

        // We can now delete the cloned registries before exiting
        clonedRegistries.clear();

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify( String... schemas ) throws LdapException
    {
        return verify( toArray( schemas ) );
    }


    /**
     * @return the namingContext
     */
    @Override
    public Dn getNamingContext()
    {
        return namingContext;
    }


    /**
     * Initializes the SchemaService
     *
     * @throws LdapException If the initialization fails
     */
    @Override
    public void initialize() throws LdapException
    {
    }


    //-----------------------------------------------------------------------------------
    // Immutable accessors
    //-----------------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public AttributeTypeRegistry getAttributeTypeRegistry()
    {
        return new ImmutableAttributeTypeRegistry( registries.getAttributeTypeRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ComparatorRegistry getComparatorRegistry()
    {
        return new ImmutableComparatorRegistry( registries.getComparatorRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitContentRuleRegistry getDITContentRuleRegistry()
    {
        return new ImmutableDitContentRuleRegistry( registries.getDitContentRuleRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DitStructureRuleRegistry getDITStructureRuleRegistry()
    {
        return new ImmutableDitStructureRuleRegistry( registries.getDitStructureRuleRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleRegistry getMatchingRuleRegistry()
    {
        return new ImmutableMatchingRuleRegistry( registries.getMatchingRuleRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRuleUseRegistry getMatchingRuleUseRegistry()
    {
        return new ImmutableMatchingRuleUseRegistry( registries.getMatchingRuleUseRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public NameFormRegistry getNameFormRegistry()
    {
        return new ImmutableNameFormRegistry( registries.getNameFormRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public NormalizerRegistry getNormalizerRegistry()
    {
        return new ImmutableNormalizerRegistry( registries.getNormalizerRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectClassRegistry getObjectClassRegistry()
    {
        return new ImmutableObjectClassRegistry( registries.getObjectClassRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapSyntaxRegistry getLdapSyntaxRegistry()
    {
        return new ImmutableLdapSyntaxRegistry( registries.getLdapSyntaxRegistry() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyntaxCheckerRegistry getSyntaxCheckerRegistry()
    {
        return new ImmutableSyntaxCheckerRegistry( registries.getSyntaxCheckerRegistry() );
    }


    /**
     * Get rid of AT's options (everything after the ';'
     * @param oid The AT's OID
     * @return The AT without its options
     */
    private String stripOptions( String oid )
    {
        int semiColonPos = oid.indexOf( ';' );

        if ( semiColonPos != -1 )
        {
            return oid.substring( 0, semiColonPos );
        }
        else
        {
            return oid;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AttributeType lookupAttributeTypeRegistry( String oid ) throws LdapException
    {
        String oidTrimmed = Strings.toLowerCaseAscii( oid ).trim();
        String oidNoOption = stripOptions( oidTrimmed );
        return registries.getAttributeTypeRegistry().lookup( oidNoOption );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public AttributeType getAttributeType( String oid )
    {
        try
        {
            // Get rid of the options
            String attributeTypeNoOptions = SchemaUtils.stripOptions( oid );
            return registries.getAttributeTypeRegistry().lookup( Strings.toLowerCaseAscii( attributeTypeNoOptions ).trim() );
        }
        catch ( LdapException lnsae )
        {
            return null;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> lookupComparatorRegistry( String oid ) throws LdapException
    {
        return registries.getComparatorRegistry().lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public MatchingRule lookupMatchingRuleRegistry( String oid ) throws LdapException
    {
        return registries.getMatchingRuleRegistry().lookup( Strings.toLowerCaseAscii( oid ).trim() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer lookupNormalizerRegistry( String oid ) throws LdapException
    {
        return registries.getNormalizerRegistry().lookup( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectClass lookupObjectClassRegistry( String oid ) throws LdapException
    {
        return registries.getObjectClassRegistry().lookup( Strings.toLowerCaseAscii( oid ).trim() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapSyntax lookupLdapSyntaxRegistry( String oid ) throws LdapException
    {
        return registries.getLdapSyntaxRegistry().lookup( Strings.toLowerCaseAscii( oid ).trim() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyntaxChecker lookupSyntaxCheckerRegistry( String oid ) throws LdapException
    {
        return registries.getSyntaxCheckerRegistry().lookup( oid );
    }


    /**
     * Check that the given OID exists in the globalOidRegistry.
     * 
     * @param schemaObject The SchemaObject to check
     * @return <tt>true</tt> if the OID exists
     */
    private boolean checkOidExist( SchemaObject schemaObject )
    {
        if ( !( schemaObject instanceof LoadableSchemaObject ) )
        {
            return registries.getGlobalOidRegistry().contains( schemaObject.getOid() );
        }

        if ( schemaObject instanceof LdapComparator<?> )
        {
            return registries.getComparatorRegistry().contains( schemaObject.getOid() );
        }

        if ( schemaObject instanceof SyntaxChecker )
        {
            return registries.getSyntaxCheckerRegistry().contains( schemaObject.getOid() );
        }

        if ( schemaObject instanceof Normalizer )
        {
            return registries.getNormalizerRegistry().contains( schemaObject.getOid() );
        }

        return false;
    }


    /**
     * Get the inner SchemaObject if it's not a C/N/SC
     * 
     * @param schemaObject The SchemaObject to retreive
     * @return The found SchemaObject
     * @throws LdapException If the SchemaObject can't be found
     */
    private SchemaObject getSchemaObject( SchemaObject schemaObject ) throws LdapException
    {
        if ( schemaObject instanceof LoadableSchemaObject )
        {
            return schemaObject;
        }
        else
        {
            return registries.getGlobalOidRegistry().getSchemaObject( schemaObject.getOid() );
        }
    }


    /**
     * Retrieve the schema name for a specific SchemaObject, or return "other" if none is found.
     * 
     * @param schemaObject The schemaObject to read
     * @return The schema name
     */
    private String getSchemaName( SchemaObject schemaObject )
    {
        String schemaName = Strings.toLowerCaseAscii( schemaObject.getSchemaName() );

        if ( Strings.isEmpty( schemaName ) )
        {
            return MetaSchemaConstants.SCHEMA_OTHER;
        }

        if ( schemaMap.get( schemaName ) == null )
        {
            return null;
        }
        else
        {
            return schemaName;
        }
    }


    private SchemaObject copy( SchemaObject schemaObject )
    {
        SchemaObject copy = null;

        if ( !( schemaObject instanceof LoadableSchemaObject ) )
        {
            copy = schemaObject.copy();
        }
        else
        {
            // Check the schemaObject here.
            if ( ( ( LoadableSchemaObject ) schemaObject ).isValid() )
            {
                copy = schemaObject;
            }
            else
            {
                // We have an invalid SchemaObject, no need to go any further
                LdapUnwillingToPerformException error = new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, I18n.err(
                    I18n.ERR_16079_INVALID_SCHEMA_OBJECT_CANNOT_BE_LOADED, schemaObject.getOid() ) );
                errorHandler.handle( LOG, error.getMessage(), error );
            }
        }

        return copy;
    }


    //-----------------------------------------------------------------------------------
    // SchemaObject operations
    //-----------------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean add( SchemaObject schemaObject ) throws LdapException
    {
        // First, clear the errors
        errorHandler.reset();

        // Clone the schemaObject
        SchemaObject copy = copy( schemaObject );

        if ( copy == null )
        {
            return false;
        }

        if ( registries.isRelaxed() )
        {
            // Apply the addition right away
            registries.add( copy, true );

            return !errorHandler.wasError();
        }
        else
        {
            // Clone, apply, check, then apply again if ok
            // The new schemaObject's OID must not already exist
            if ( checkOidExist( copy ) )
            {
                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.OID_ALREADY_REGISTERED, I18n.err( I18n.ERR_16036_OID_NOT_UNIQUE, 
                        schemaObject.getOid() ) );
                ldapSchemaException.setSourceObject( schemaObject );
                errorHandler.handle( LOG, ldapSchemaException.getMessage(), ldapSchemaException );

                return false;
            }

            // Build the new AttributeType from the given entry
            String schemaName = getSchemaName( copy );

            if ( schemaName == null )
            {
                // The schema associated with the SchemaaObject does not exist. This is not valid.

                LdapSchemaException ldapSchemaException = new LdapSchemaException(
                    LdapSchemaExceptionCodes.NONEXISTENT_SCHEMA, I18n.err( I18n.ERR_16037_NON_EXISTING_SCHEMA, 
                        schemaObject.getOid(), copy.getSchemaName() ) );
                ldapSchemaException.setSourceObject( schemaObject );
                ldapSchemaException.setRelatedId( copy.getSchemaName() );
                errorHandler.handle( LOG, ldapSchemaException.getMessage(), ldapSchemaException );

                return false;
            }

            // At this point, the constructed AttributeType has not been checked against the
            // existing Registries. It may be broken (missing SUP, or such), it will be checked
            // there, if the schema and the AttributeType are both enabled.
            Schema schema = getLoadedSchema( schemaName );

            if ( schema == null )
            {
                // The SchemaObject must be associated with an existing schema
                String msg = I18n.err( I18n.ERR_16038_NOT_ASSOCIATED_TO_A_SCHEMA, copy.getOid() );
                Throwable error = new LdapProtocolErrorException( msg );
                errorHandler.handle( LOG, msg, error );
                return false;
            }

            if ( schema.isEnabled() && copy.isEnabled() )
            {
                // As we may break the registries, work on a cloned registries
                Registries clonedRegistries = null;

                try
                {
                    clonedRegistries = registries.clone();
                }
                catch ( CloneNotSupportedException cnse )
                {
                    throw new LdapOtherException( cnse.getMessage(), cnse );
                }

                // Inject the new SchemaObject in the cloned registries
                clonedRegistries.add( copy, true );

                // Remove the cloned registries
                clonedRegistries.clear();

                // If we didn't get any error, apply the addition to the real registries
                if ( !errorHandler.wasError() )
                {
                    // Copy again as the clonedRegistries clear has removed the previous copy
                    copy = copy( schemaObject );

                    // Apply the addition to the real registries
                    registries.add( copy, true );

                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.msg( I18n.MSG_16019_ENABLED_SCHEMA_ADDED, copy.getName(), schemaName ) );
                    }

                    return true;
                }
                else
                {
                    // We have some error : reject the addition and get out
                    errorHandler.handle( LOG, I18n.msg( I18n.MSG_16020_CANNOT_LOAD_SCHEMAOBJECT, 
                            copy.getOid(), Strings.listToString( errorHandler.getErrors() ) ), null );
                    return false;
                }
            }
            else
            {
                // At least, we register the OID in the globalOidRegistry, and associates it with the
                // schema
                registries.associateWithSchema( copy );

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_16021_ADDED_INTO_DISABLED_SCHEMA, copy.getName(), schemaName ) );
                }
                
                return !errorHandler.wasError();
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean delete( SchemaObject schemaObject ) throws LdapException
    {
        // First, clear the errors
        errorHandler.reset();

        if ( registries.isRelaxed() )
        {
            // Apply the addition right away
            registries.delete( schemaObject );

            return !errorHandler.wasError();
        }
        else
        {
            // Clone, apply, check, then apply again if ok
            // The new schemaObject's OID must exist
            if ( !checkOidExist( schemaObject ) )
            {
                Throwable error = new LdapProtocolErrorException( I18n.err( I18n.ERR_16039_OID_DOES_NOT_EXIST, 
                    schemaObject.getOid() ) );
                errorHandler.handle( LOG, error.getMessage(), error );
                return false;
            }

            // Get the SchemaObject to delete if it's not a LoadableSchemaObject
            SchemaObject toDelete = getSchemaObject( schemaObject );

            // First check that this SchemaObject does not have any referencing SchemaObjects
            Set<SchemaObjectWrapper> referencing = registries.getReferencing( toDelete );

            if ( ( referencing != null ) && !referencing.isEmpty() )
            {
                String msg = I18n.err( I18n.ERR_16040_CANNOT_REMOVE_FROM_REGISTRY, schemaObject.getOid(), 
                    Strings.setToString( referencing ) );

                Throwable error = new LdapProtocolErrorException( msg );
                errorHandler.handle( LOG, msg, error );
                return false;
            }

            String schemaName = getSchemaName( toDelete );

            // At this point, the deleted AttributeType may be referenced, it will be checked
            // there, if the schema and the AttributeType are both enabled.
            Schema schema = getLoadedSchema( schemaName );

            if ( schema == null )
            {
                // The SchemaObject must be associated with an existing schema
                String msg = I18n.err( I18n.ERR_16041_CANNOT_DELETE_SCHEMA_OBJECT, schemaObject.getOid() );
                Throwable error = new LdapProtocolErrorException( msg );
                errorHandler.handle( LOG, msg, error );
                return false;
            }

            if ( schema.isEnabled() && schemaObject.isEnabled() )
            {
                // As we may break the registries, work on a cloned registries
                Registries clonedRegistries = null;

                try
                {
                    clonedRegistries = registries.clone();
                }
                catch ( CloneNotSupportedException cnse )
                {
                    throw new LdapOtherException( cnse.getMessage(), cnse );
                }

                // Delete the SchemaObject from the cloned registries
                clonedRegistries.delete( toDelete );

                // Remove the cloned registries
                clonedRegistries.clear();

                // If we didn't get any error, apply the deletion to the real retistries
                if ( !errorHandler.wasError() )
                {
                    // Apply the deletion to the real registries
                    registries.delete( toDelete );

                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.msg( I18n.MSG_16022_REMOVED_FROM_ENABLED_SCHEMA, toDelete.getName(), schemaName ) );
                    }

                    return true;
                }
                else
                {
                    // We have some error : reject the deletion and get out
                    errorHandler.handle( LOG, I18n.msg( I18n.MSG_16023_CANNOT_DELETE_SCHEMAOBJECT, 
                            schemaObject.getOid(), Strings.listToString( errorHandler.getErrors() ) ), null );

                    return false;
                }
            }
            else
            {
                // At least, we register the OID in the globalOidRegistry, and associates it with the
                // schema
                registries.associateWithSchema( schemaObject );

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_16024_REMOVED_FROM_DISABLED_SCHEMA, schemaObject.getName(), schemaName ) );
                }
                
                return !errorHandler.wasError();
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, OidNormalizer> getNormalizerMapping()
    {
        return registries.getAttributeTypeRegistry().getNormalizerMapping();
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("rawtypes")
    @Override
    public OidRegistry getGlobalOidRegistry()
    {
        return registries.getGlobalOidRegistry();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Schema getLoadedSchema( String schemaName )
    {
        return schemaMap.get( schemaName );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSchemaLoaded( String schemaName )
    {
        try
        {
            Schema schema = schemaMap.get( schemaName );
            
            return schema != null;
        }
        catch ( Exception e )
        {
            return false;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterAttributeType( String attributeTypeOid ) throws LdapException
    {
        return registries.getAttributeTypeRegistry().unregister( attributeTypeOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterComparator( String comparatorOid ) throws LdapException
    {
        return registries.getComparatorRegistry().unregister( comparatorOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterDitControlRule( String ditControlRuleOid ) throws LdapException
    {
        return registries.getDitContentRuleRegistry().unregister( ditControlRuleOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterDitStructureRule( String ditStructureRuleOid ) throws LdapException
    {
        return registries.getDitStructureRuleRegistry().unregister( ditStructureRuleOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterLdapSyntax( String ldapSyntaxOid ) throws LdapException
    {
        return registries.getLdapSyntaxRegistry().unregister( ldapSyntaxOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterMatchingRule( String matchingRuleOid ) throws LdapException
    {
        return registries.getMatchingRuleRegistry().unregister( matchingRuleOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterMatchingRuleUse( String matchingRuleUseOid ) throws LdapException
    {
        return registries.getMatchingRuleUseRegistry().unregister( matchingRuleUseOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterNameForm( String nameFormOid ) throws LdapException
    {
        return registries.getNameFormRegistry().unregister( nameFormOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterNormalizer( String normalizerOid ) throws LdapException
    {
        return registries.getNormalizerRegistry().unregister( normalizerOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterObjectClass( String objectClassOid ) throws LdapException
    {
        return registries.getObjectClassRegistry().unregister( objectClassOid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SchemaObject unregisterSyntaxChecker( String syntaxCheckerOid ) throws LdapException
    {
        return registries.getSyntaxCheckerRegistry().unregister( syntaxCheckerOid );
    }


    /**
     * Tells if the SchemaManager is permissive or if it must be checked
     * against inconsistencies.
     *
     * @return True if SchemaObjects can be added even if they break the consistency
     */
    @Override
    public boolean isRelaxed()
    {
        return isRelaxed;
    }

    
    /**
     * Tells if the SchemaManager is strict.
     *
     * @return True if SchemaObjects cannot be added if they break the consistency
     */
    @Override
    public boolean isStrict()
    {
        return !isRelaxed;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> listDependentSchemaNames( String schemaName )
    {
        return schemaDependencies.get( schemaName );
    }


    /**
     * Change the SchemaManager to a relaxed mode, where invalid SchemaObjects
     * can be registered.
     */
    @Override
    public void setRelaxed()
    {
        isRelaxed = RELAXED;
    }


    /**
     * Change the SchemaManager to a strict mode, where invalid SchemaObjects
     * cannot be registered.
     */
    @Override
    public void setStrict()
    {
        isRelaxed = STRICT;
    }


    public SchemaErrorHandler getErrorHandler()
    {
        return errorHandler;
    }


    public void setErrorHandler( SchemaErrorHandler errorHandler )
    {
        this.errorHandler = errorHandler;
        registries.setErrorHandler( errorHandler );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDisabled( String schemaName )
    {
        Schema schema = registries.getLoadedSchema( schemaName );

        return ( schema != null ) && schema.isDisabled();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDisabled( Schema schema )
    {
        return ( schema != null ) && schema.isDisabled();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEnabled( String schemaName )
    {
        Schema schema = registries.getLoadedSchema( schemaName );

        return ( schema != null ) && schema.isEnabled();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isEnabled( Schema schema )
    {
        return ( schema != null ) && schema.isEnabled();
    }
}
