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


import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.LoadableSchemaObject;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker.SCBuilder;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescription;
import org.apache.directory.api.ldap.model.schema.parsers.NormalizerDescription;
import org.apache.directory.api.ldap.model.schema.parsers.SyntaxCheckerDescription;
import org.apache.directory.api.ldap.model.schema.registries.DefaultSchema;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.util.StringConstants;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Showing how it's done ...
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaEntityFactory implements EntityFactory
{
    /** Slf4j logger */
    private static final Logger LOG = LoggerFactory.getLogger( SchemaEntityFactory.class );

    /** The empty string list. */
    private static final List<String> EMPTY_LIST = new ArrayList<>();

    /** The empty string array. */
    private static final String[] EMPTY_ARRAY = new String[]
        {};

    /** A special ClassLoader that loads a class from the bytecode attribute */
    private final AttributeClassLoader classLoader;


    /**
     * Instantiates a new schema entity factory.
     */
    public SchemaEntityFactory()
    {
        this.classLoader = AccessController.doPrivileged( new PrivilegedAction<AttributeClassLoader>()
        {
            @Override
            public AttributeClassLoader run() 
            {
                return new AttributeClassLoader();
            }
        } );
    }


    /**
     * Get an OID from an entry. Handles the bad cases (null OID,
     * not a valid OID, ...)
     * 
     * @param entry The entry to process
     * @param objectType The type of processed SchemaObject
     * @param strict If we want a strict control of the OID
     * @return The found OID
     * @throws LdapInvalidAttributeValueException If the OID is not valid 
     */
    private String getOid( Entry entry, String objectType, boolean strict ) throws LdapInvalidAttributeValueException
    {
        // The OID
        Attribute mOid = entry.get( MetaSchemaConstants.M_OID_AT );

        if ( mOid == null )
        {
            String msg = I18n.err( I18n.ERR_16011_NULL_ATTRIBUTE, objectType, MetaSchemaConstants.M_OID_AT );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        String oid = mOid.getString();

        if ( strict && !Oid.isOid( oid ) )
        {
            String msg = I18n.err( I18n.ERR_16012_INVALID_COMPARATOR_OID, oid );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, msg );
        }

        return oid;
    }


    /**
     * Get an OID from an entry. Handles the bad cases (null OID,
     * not a valid OID, ...)
     * 
     * @param description The schemaObject description
     * @param objectType The type of SchemaObject being processed
     * @return The found OID
     * @throws LdapInvalidAttributeValueException If the OID is invalid
     */
    private String getOid( SchemaObject description, String objectType ) throws LdapInvalidAttributeValueException
    {
        // The OID
        String oid = description.getOid();

        if ( oid == null )
        {
            String msg = I18n.err( I18n.ERR_16011_NULL_ATTRIBUTE, objectType, MetaSchemaConstants.M_OID_AT );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        if ( !Oid.isOid( oid ) )
        {
            String msg = I18n.err( I18n.ERR_16012_INVALID_COMPARATOR_OID, oid );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, msg );
        }

        return oid;
    }


    /**
     * Check that the Entry is not null
     * 
     * @param entry The entry to check
     * @param schemaEntity The message to log if the entry is invalid
     */
    private void checkEntry( Entry entry, String schemaEntity )
    {
        if ( entry == null )
        {
            String msg = I18n.err( I18n.ERR_16013_NULL_ENTRY, schemaEntity );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }
    }


    /**
     * Check that the Description is not null
     * 
     * @param description description entry to check
     * @param schemaEntity The message to log if the description is invalid
     */
    private void checkDescription( SchemaObject description, String schemaEntity )
    {
        if ( description == null )
        {
            String msg = I18n.err( I18n.ERR_16014_NULL_SCHEMA_DESC, schemaEntity );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }
    }


    /**
     * Get the schema from its name. Return the Other reference if there
     * is no schema name. Throws a NPE if the schema is not loaded.
     * 
     * @param schemaName The schema name to fetch
     * @param registries The registries where we get the schema from
     * @return the found Schema
     */
    private Schema getSchema( String schemaName, Registries registries )
    {
        if ( Strings.isEmpty( schemaName ) )
        {
            schemaName = MetaSchemaConstants.SCHEMA_OTHER;
        }

        Schema schema = registries.getLoadedSchema( schemaName );

        if ( schema == null )
        {
            String msg = I18n.err( I18n.ERR_16015_NON_EXISTENT_SCHEMA, schemaName );
            LOG.error( msg );
        }

        return schema;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Schema getSchema( Entry entry ) throws LdapException
    {
        String name;
        String owner;
        String[] dependencies = EMPTY_ARRAY;
        boolean isDisabled = false;

        if ( entry == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_16016_NULL_ENTRY ) );
        }

        if ( entry.get( SchemaConstants.CN_AT ) == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_16017_INVALID_CN_AT ) );
        }

        name = entry.get( SchemaConstants.CN_AT ).getString();

        if ( entry.get( SchemaConstants.CREATORS_NAME_AT ) == null )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_16018_INVALID_AT, SchemaConstants.CREATORS_NAME_AT ) );
        }

        owner = entry.get( SchemaConstants.CREATORS_NAME_AT ).getString();

        if ( entry.get( MetaSchemaConstants.M_DISABLED_AT ) != null )
        {
            String value = entry.get( MetaSchemaConstants.M_DISABLED_AT ).getString();
            value = Strings.upperCase( value );
            isDisabled = "TRUE".equalsIgnoreCase( value );
        }

        if ( entry.get( MetaSchemaConstants.M_DEPENDENCIES_AT ) != null )
        {
            Set<String> depsSet = new HashSet<>();
            Attribute depsAttr = entry.get( MetaSchemaConstants.M_DEPENDENCIES_AT );

            for ( Value value : depsAttr )
            {
                depsSet.add( value.getString() );
            }

            dependencies = depsSet.toArray( EMPTY_ARRAY );
        }

        return new DefaultSchema( null, name, owner, dependencies, isDisabled );
    }


    /**
     * Class load a SyntaxChecker instance
     * 
     * @param schemaManager The SchemaManager
     * @param oid The SyntaxChecker OID
     * @param className The class name associated with the SyntaxChecker
     * @param byteCode The SyntaxChecker class bytecode
     * @return The loaded SyntaxChecker
     * @throws LdapException If the SyntaxChecker cannot be loaded
     */
    private SyntaxChecker classLoadSyntaxChecker( SchemaManager schemaManager, String oid, String className,
        Attribute byteCode ) throws LdapException
    {
        // Try to class load the syntaxChecker
        Class<?> clazz;
        SyntaxChecker syntaxChecker;
        String byteCodeStr = StringConstants.EMPTY;

        if ( byteCode == null )
        {
            try
            {
                clazz = Class.forName( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16048_CANNOT_FIND_SC_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16049_CANNOT_FIND_SC_CLASS, cnfe.getMessage() ) );
            }
        }
        else
        {
            classLoader.setAttribute( byteCode );
            
            try
            {
                clazz = classLoader.loadClass( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16050_CANNOT_LOAD_SC_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16051_CANNOT_LOAD_SC_CLASS, cnfe.getMessage() ) );
            }
            
            byteCodeStr = Base64.getEncoder().encodeToString( byteCode.getBytes() );
        }

        // Create the syntaxChecker instance
        try
        {
            Method builder = clazz.getMethod( "builder", ( Class<?>[] ) null );
            syntaxChecker = ( SyntaxChecker ) ( ( SCBuilder ) builder.invoke( null, ( Object[] ) null ) ).setOid( oid ).build();
        }
        catch ( NoSuchMethodException nsme )
        {
            LOG.error( I18n.err( I18n.ERR_16052_CANNOT_INST_SC_CTOR, className ) );
            throw new LdapSchemaException( I18n.err( I18n.ERR_16053_CANNOT_INST_SC_CLASS, nsme.getMessage() ) );
        }
        catch ( InvocationTargetException | IllegalAccessException e )
        {
            LOG.error( I18n.err( I18n.ERR_16054_CANNOT_ACCESS_SC_CTOR, className ) );
            throw new LdapSchemaException( I18n.err( I18n.ERR_16055_CANNOT_ACCESS_SC_CLASS, e.getMessage() ) );
        }

        // Update the common fields
        syntaxChecker.setBytecode( byteCodeStr );
        syntaxChecker.setFqcn( className );

        // Inject the SchemaManager for the comparator who needs it
        syntaxChecker.setSchemaManager( schemaManager );

        return syntaxChecker;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyntaxChecker getSyntaxChecker( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException
    {
        checkEntry( entry, SchemaConstants.SYNTAX_CHECKER );

        // The SyntaxChecker OID
        String oid = getOid( entry, SchemaConstants.SYNTAX_CHECKER, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested Normalizer
            String msg = I18n.err( I18n.ERR_16019_CANNOT_ADD_SC, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16020_CANNOT_ADD_SC_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // The FQCN
        String className = getFqcn( entry, SchemaConstants.SYNTAX_CHECKER );

        // The ByteCode
        Attribute byteCode = entry.get( MetaSchemaConstants.M_BYTECODE_AT );

        try
        {
            // Class load the syntaxChecker
            SyntaxChecker syntaxChecker = classLoadSyntaxChecker( schemaManager, oid, className, byteCode );

            // Update the common fields
            setSchemaObjectProperties( syntaxChecker, entry, schema );

            // return the resulting syntaxChecker
            return syntaxChecker;
        }
        catch ( Exception e )
        {
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyntaxChecker getSyntaxChecker( SchemaManager schemaManager,
        SyntaxCheckerDescription syntaxCheckerDescription, Registries targetRegistries, String schemaName )
        throws LdapException
    {
        checkDescription( syntaxCheckerDescription, SchemaConstants.SYNTAX_CHECKER );

        // The Comparator OID
        String oid = getOid( syntaxCheckerDescription, SchemaConstants.SYNTAX_CHECKER );

        // Get the schema
        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is not loaded. We can't create the requested SyntaxChecker
            String msg = I18n.err( I18n.ERR_16019_CANNOT_ADD_SC, syntaxCheckerDescription.getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        // The FQCN
        String fqcn = getFqcn( syntaxCheckerDescription, SchemaConstants.SYNTAX_CHECKER );

        // get the byteCode
        Attribute byteCode = getByteCode( syntaxCheckerDescription, SchemaConstants.SYNTAX_CHECKER );

        // Class load the SyntaxChecker
        SyntaxChecker syntaxChecker = classLoadSyntaxChecker( schemaManager, oid, fqcn, byteCode );

        // Update the common fields
        setSchemaObjectProperties( syntaxChecker, syntaxCheckerDescription, schema );

        return syntaxChecker;
    }


    /**
     * Class load a comparator instances
     * 
     * @param schemaManager The SchemaManager
     * @param oid The comparator OID
     * @param className The class name associated with the comparator
     * @param byteCode The comparator class bytecode
     * @return The loaded comparator
     * @throws LdapException If the comparator cannot be loaded
     */
    private LdapComparator<?> classLoadComparator( SchemaManager schemaManager, String oid, String className,
        Attribute byteCode ) throws LdapException
    {
        // Try to class load the comparator
        LdapComparator<?> comparator;
        Class<?> clazz;
        String byteCodeStr = StringConstants.EMPTY;

        if ( byteCode == null )
        {
            try
            {
                clazz = Class.forName( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16056_CANNOT_FIND_CMP_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16057_CANNOT_FIND_CMP_CLASS, cnfe.getMessage() ) );
            }
        }
        else
        {
            classLoader.setAttribute( byteCode );
            
            try
            {
                clazz = classLoader.loadClass( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16058_CANNOT_LOAD_CMP_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16059_CANNOT_LOAD_CMP_CLASS, cnfe.getMessage() ) );
            }

            byteCodeStr = Base64.getEncoder().encodeToString( byteCode.getBytes() );
        }

        // Create the comparator instance. Either we have a no argument constructor,
        // or we have one which takes an OID. Lets try the one with an OID argument first
        try
        {
            Constructor<?> constructor = clazz.getConstructor( new Class[]
                { String.class } );
            
            try
            {
                comparator = ( LdapComparator<?> ) constructor.newInstance( oid );
            }
            catch ( InvocationTargetException ite )
            {
                LOG.error( I18n.err( I18n.ERR_16060_CANNOT_INVOKE_CMP_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16061_CANNOT_INVOKE_CMP_CLASS, ite.getMessage() ) );
            }
            catch ( InstantiationException ie )
            {
                LOG.error( I18n.err( I18n.ERR_16062_CANNOT_INST_CMP_CTOR_CLASS, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16063_CANNOT_INST_CMP_CLASS, ie.getMessage() ) );
            }
            catch ( IllegalAccessException ie )
            {
                LOG.error( I18n.err( I18n.ERR_16064_CANNOT_ACCESS_CMP_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16065_CANNOT_ACCESS_CMP_CLASS, ie.getMessage() ) );
            }
        }
        catch ( NoSuchMethodException nsme )
        {
            // Ok, let's try with the constructor without argument.
            // In this case, we will have to check that the OID is the same than
            // the one we got in the Comparator entry
            try
            {
                clazz.getConstructor();
            }
            catch ( NoSuchMethodException nsme2 )
            {
                LOG.error( I18n.err( I18n.ERR_16066_CANNOT_FIND_CMP_CTOR_METH_CLASS, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16067_CANNOT_FIND_CMP_CTOR_METH, nsme2.getMessage() ) );
            }
            
            try
            { 
                comparator = ( LdapComparator<?> ) clazz.newInstance();
            }
            catch ( InstantiationException ie )
            {
                LOG.error( I18n.err( I18n.ERR_16062_CANNOT_INST_CMP_CTOR_CLASS, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16063_CANNOT_INST_CMP_CLASS, ie.getMessage() ) );
            }
            catch ( IllegalAccessException iae )
            {
                LOG.error( I18n.err( I18n.ERR_16064_CANNOT_ACCESS_CMP_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16065_CANNOT_ACCESS_CMP_CLASS, iae.getMessage() ) );
            }

            if ( !comparator.getOid().equals( oid ) )
            {
                String msg = I18n.err( I18n.ERR_16021_DIFFERENT_COMPARATOR_OID, oid, comparator.getOid() );
                throw new LdapInvalidAttributeValueException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg, nsme );
            }
        }

        // Update the loadable fields
        comparator.setBytecode( byteCodeStr );
        comparator.setFqcn( className );

        // Inject the SchemaManager for the comparator who needs it
        comparator.setSchemaManager( schemaManager );

        return comparator;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> getLdapComparator( SchemaManager schemaManager,
        LdapComparatorDescription comparatorDescription, Registries targetRegistries, String schemaName )
        throws LdapException
    {
        checkDescription( comparatorDescription, SchemaConstants.COMPARATOR );

        // The Comparator OID
        String oid = getOid( comparatorDescription, SchemaConstants.COMPARATOR );

        // Get the schema
        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is not loaded. We can't create the requested Comparator
            String msg = I18n.err( I18n.ERR_16022_CANNOT_ADD_CMP, comparatorDescription.getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        // The FQCN
        String fqcn = getFqcn( comparatorDescription, SchemaConstants.COMPARATOR );

        // get the byteCode
        Attribute byteCode = getByteCode( comparatorDescription, SchemaConstants.COMPARATOR );

        // Class load the comparator
        LdapComparator<?> comparator = classLoadComparator( schemaManager, oid, fqcn, byteCode );

        // Update the common fields
        setSchemaObjectProperties( comparator, comparatorDescription, schema );

        return comparator;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapComparator<?> getLdapComparator( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException
    {
        checkEntry( entry, SchemaConstants.COMPARATOR );

        // The Comparator OID
        String oid = getOid( entry, SchemaConstants.COMPARATOR, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested Comparator
            String msg = I18n.err( I18n.ERR_16022_CANNOT_ADD_CMP, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16023_CANNOT_ADD_CMP_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // The FQCN
        String fqcn = getFqcn( entry, SchemaConstants.COMPARATOR );

        // The ByteCode
        Attribute byteCode = entry.get( MetaSchemaConstants.M_BYTECODE_AT );

        try
        {
            // Class load the comparator
            LdapComparator<?> comparator = classLoadComparator( schemaManager, oid, fqcn, byteCode );

            // Update the common fields
            setSchemaObjectProperties( comparator, entry, schema );

            // return the resulting comparator
            return comparator;
        }
        catch ( Exception e )
        {
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getMessage(), e );
        }
    }


    /**
     * Class load a normalizer instances
     * 
     * @param schemaManager The SchemaManager
     * @param oid The normalizer OID
     * @param className The class name associated with the normalizer
     * @param byteCode The normalizer class bytecode
     * @return The loaded normalizer
     * @throws LdapException If the normalizer cannot be loaded
     */
    private Normalizer classLoadNormalizer( SchemaManager schemaManager, String oid, String className,
        Attribute byteCode ) throws LdapException
    {
        // Try to class load the normalizer
        Class<?> clazz;
        Normalizer normalizer;
        String byteCodeStr = StringConstants.EMPTY;

        if ( byteCode == null )
        {
            try
            {  
                clazz = Class.forName( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16068_CANNOT_FIND_NORM_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16069_CANNOT_FIND_NORM_CLASS, cnfe.getMessage() ) );
            }
        }
        else
        {
            classLoader.setAttribute( byteCode );
            
            try
            {
                clazz = classLoader.loadClass( className );
            }
            catch ( ClassNotFoundException cnfe )
            {
                LOG.error( I18n.err( I18n.ERR_16070_CANNOT_LOAD_NORM_CTOR, className ) );
                throw new LdapSchemaException( I18n.err( I18n.ERR_16071_CANNOT_LOAD_NORM_CLASS, cnfe.getMessage() ) );
            }

            byteCodeStr = Base64.getEncoder().encodeToString( byteCode.getBytes() );
        }

        // Create the normalizer instance
        try
        { 
            normalizer = ( Normalizer ) clazz.newInstance();
        }
        catch ( InstantiationException ie )
        {
            LOG.error( I18n.err( I18n.ERR_16072_CANNOT_INST_NORM_CTOR_CLASS, className ) );
            throw new LdapSchemaException( I18n.err( I18n.ERR_16073_CANNOT_INST_NORM_CLASS, ie.getMessage() ) );
        }
        catch ( IllegalAccessException iae )
        {
            LOG.error( I18n.err( I18n.ERR_16074_CANNOT_ACCESS_NORM_CTOR_CLASS, className ) );
            throw new LdapSchemaException( I18n.err( I18n.ERR_16075_CANNOT_ACCESS_NORM_CTOR, iae.getMessage() ) );
        }

        // Update the common fields
        normalizer.setBytecode( byteCodeStr );
        normalizer.setFqcn( className );

        // Inject the new OID, as the loaded normalizer might have its own
        normalizer.setOid( oid );

        // Inject the SchemaManager for the normalizer who needs it
        normalizer.setSchemaManager( schemaManager );

        return normalizer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer getNormalizer( SchemaManager schemaManager, NormalizerDescription normalizerDescription,
        Registries targetRegistries, String schemaName ) throws LdapException
    {
        checkDescription( normalizerDescription, SchemaConstants.NORMALIZER );

        // The Comparator OID
        String oid = getOid( normalizerDescription, SchemaConstants.NORMALIZER );

        // Get the schema
        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is not loaded. We can't create the requested Normalizer
            String msg = I18n.err( I18n.ERR_16024_CANNOT_ADD_NORMALIZER, normalizerDescription.getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        // The FQCN
        String fqcn = getFqcn( normalizerDescription, SchemaConstants.NORMALIZER );

        // get the byteCode
        Attribute byteCode = getByteCode( normalizerDescription, SchemaConstants.NORMALIZER );

        // Class load the normalizer
        Normalizer normalizer = classLoadNormalizer( schemaManager, oid, fqcn, byteCode );

        // Update the common fields
        setSchemaObjectProperties( normalizer, normalizerDescription, schema );

        return normalizer;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer getNormalizer( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException
    {
        checkEntry( entry, SchemaConstants.NORMALIZER );

        // The Normalizer OID
        String oid = getOid( entry, SchemaConstants.NORMALIZER, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested Normalizer
            String msg = I18n.err( I18n.ERR_16024_CANNOT_ADD_NORMALIZER, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16025_CANNOT_ADD_NORMALIZER_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // The FQCN
        String className = getFqcn( entry, SchemaConstants.NORMALIZER );

        // The ByteCode
        Attribute byteCode = entry.get( MetaSchemaConstants.M_BYTECODE_AT );

        try
        {
            // Class load the Normalizer
            Normalizer normalizer = classLoadNormalizer( schemaManager, oid, className, byteCode );

            // Update the common fields
            setSchemaObjectProperties( normalizer, entry, schema );

            // return the resulting Normalizer
            return normalizer;
        }
        catch ( Exception e )
        {
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getMessage(), e );
        }
    }


    /**
     * {@inheritDoc}
     * @throws LdapInvalidAttributeValueException If the Syntax does not exist
     * @throws LdapUnwillingToPerformException If the schema is not loaded
     */
    @Override
    public LdapSyntax getSyntax( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapInvalidAttributeValueException, LdapUnwillingToPerformException
    {
        checkEntry( entry, SchemaConstants.SYNTAX );

        // The Syntax OID
        String oid = getOid( entry, SchemaConstants.SYNTAX, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested Syntax
            String msg = I18n.err( I18n.ERR_16026_CANNOT_ADD_SYNTAX, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16027_CANNOT_ADD_SYNTAX_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // Create the new LdapSyntax instance
        LdapSyntax syntax = new LdapSyntax( oid );

        // Common properties
        setSchemaObjectProperties( syntax, entry, schema );

        return syntax;
    }


    /**
     * {@inheritDoc}
     * @throws LdapInvalidAttributeValueException If the MatchingRule does not exist
     * @throws LdapUnwillingToPerformException If the schema is not loaded
     */
    @Override
    public MatchingRule getMatchingRule( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapUnwillingToPerformException, LdapInvalidAttributeValueException
    {
        checkEntry( entry, SchemaConstants.MATCHING_RULE );

        // The MatchingRule OID
        String oid = getOid( entry, SchemaConstants.MATCHING_RULE, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested MatchingRule
            String msg = I18n.err( I18n.ERR_16028_CANNOT_ADD_MR, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16029_CANNOT_ADD_MR_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        MatchingRule matchingRule = new MatchingRule( oid );

        // The syntax field
        Attribute mSyntax = entry.get( MetaSchemaConstants.M_SYNTAX_AT );

        if ( mSyntax != null )
        {
            matchingRule.setSyntaxOid( mSyntax.getString() );
        }

        // The normalizer and comparator fields will be updated when we will
        // apply the registry

        // Common properties
        setSchemaObjectProperties( matchingRule, entry, schema );

        return matchingRule;
    }


    /**
     * Create a list of string from a multivalued attribute's values
     * 
     * @param attr The Attribute to read
     * @return The list of values as Strings
     */
    private List<String> getStrings( Attribute attr )
    {
        if ( attr == null )
        {
            return EMPTY_LIST;
        }

        List<String> strings = new ArrayList<>( attr.size() );

        for ( Value value : attr )
        {
            strings.add( value.getString() );
        }

        return strings;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectClass getObjectClass( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapException
    {
        checkEntry( entry, SchemaConstants.OBJECT_CLASS );

        // The ObjectClass OID
        String oid = getOid( entry, SchemaConstants.OBJECT_CLASS, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded. We can't create the requested ObjectClass
            String msg = I18n.err( I18n.ERR_16030_CANNOT_ADD_OC, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16031_CANNOT_ADD_OC_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // Create the ObjectClass instance
        ObjectClass oc = new ObjectClass( oid );

        // The Sup field
        Attribute mSuperiors = entry.get( MetaSchemaConstants.M_SUP_OBJECT_CLASS_AT );

        if ( mSuperiors != null )
        {
            oc.setSuperiorOids( getStrings( mSuperiors ) );
        }

        // The May field
        Attribute mMay = entry.get( MetaSchemaConstants.M_MAY_AT );

        if ( mMay != null )
        {
            oc.setMayAttributeTypeOids( getStrings( mMay ) );
        }

        // The Must field
        Attribute mMust = entry.get( MetaSchemaConstants.M_MUST_AT );

        if ( mMust != null )
        {
            oc.setMustAttributeTypeOids( getStrings( mMust ) );
        }

        // The objectClassType field
        Attribute mTypeObjectClass = entry.get( MetaSchemaConstants.M_TYPE_OBJECT_CLASS_AT );

        if ( mTypeObjectClass != null )
        {
            String type = mTypeObjectClass.getString();
            oc.setType( ObjectClassTypeEnum.getClassType( type ) );
        }

        // Common properties
        setSchemaObjectProperties( oc, entry, schema );

        return oc;
    }


    /**
     * {@inheritDoc}
     * @throws LdapInvalidAttributeValueException If the AttributeType does not exist
     * @throws LdapUnwillingToPerformException If the schema is not loaded
     */
    @Override
    public AttributeType getAttributeType( SchemaManager schemaManager, Entry entry, Registries targetRegistries,
        String schemaName ) throws LdapInvalidAttributeValueException, LdapUnwillingToPerformException
    {
        checkEntry( entry, SchemaConstants.ATTRIBUTE_TYPE );

        // The AttributeType OID
        String oid = getOid( entry, SchemaConstants.ATTRIBUTE_TYPE, schemaManager.isStrict() );

        // Get the schema
        if ( !schemaManager.isSchemaLoaded( schemaName ) )
        {
            // The schema is not loaded, this is an error
            String msg = I18n.err( I18n.ERR_16032_CANNOT_ADD_AT, entry.getDn().getName(), schemaName );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new LdapUnwillingToPerformException( ResultCodeEnum.UNWILLING_TO_PERFORM, msg );
        }

        Schema schema = getSchema( schemaName, targetRegistries );

        if ( schema == null )
        {
            // The schema is disabled. We still have to update the backend
            if ( LOG.isInfoEnabled() )
            {
                LOG.info( I18n.err( I18n.ERR_16033_CANNOT_ADD_AT_IN_REGISTRY, entry.getDn().getName(), schemaName ) );
            }
            
            schema = schemaManager.getLoadedSchema( schemaName );
        }

        // Create the new AttributeType
        AttributeType attributeType = new AttributeType( oid );
        
        if ( schemaManager.isRelaxed() )
        {
            attributeType.setRelaxed( true );
        }

        // Syntax
        Attribute mSyntax = entry.get( MetaSchemaConstants.M_SYNTAX_AT );

        if ( ( mSyntax != null ) && ( mSyntax.get() != null ) )
        {
            attributeType.setSyntaxOid( mSyntax.getString() );
        }

        // Syntax Length
        Attribute mSyntaxLength = entry.get( MetaSchemaConstants.M_LENGTH_AT );

        if ( mSyntaxLength != null )
        {
            attributeType.setSyntaxLength( Integer.parseInt( mSyntaxLength.getString() ) );
        }

        // Equality
        Attribute mEquality = entry.get( MetaSchemaConstants.M_EQUALITY_AT );

        if ( mEquality != null )
        {
            attributeType.setEqualityOid( mEquality.getString() );
        }

        // Ordering
        Attribute mOrdering = entry.get( MetaSchemaConstants.M_ORDERING_AT );

        if ( mOrdering != null )
        {
            attributeType.setOrderingOid( mOrdering.getString() );
        }

        // Substr
        Attribute mSubstr = entry.get( MetaSchemaConstants.M_SUBSTR_AT );

        if ( mSubstr != null )
        {
            attributeType.setSubstringOid( mSubstr.getString() );
        }

        Attribute mSupAttributeType = entry.get( MetaSchemaConstants.M_SUP_ATTRIBUTE_TYPE_AT );

        // Sup
        if ( mSupAttributeType != null )
        {
            attributeType.setSuperiorOid( mSupAttributeType.getString() );
        }

        // isCollective
        Attribute mCollective = entry.get( MetaSchemaConstants.M_COLLECTIVE_AT );

        if ( mCollective != null )
        {
            String val = mCollective.getString();
            attributeType.setCollective( "TRUE".equalsIgnoreCase( val ) );
        }

        // isSingleValued
        Attribute mSingleValued = entry.get( MetaSchemaConstants.M_SINGLE_VALUE_AT );

        if ( mSingleValued != null )
        {
            String val = mSingleValued.getString();
            attributeType.setSingleValued( "TRUE".equalsIgnoreCase( val ) );
        }

        // isReadOnly
        Attribute mNoUserModification = entry.get( MetaSchemaConstants.M_NO_USER_MODIFICATION_AT );

        if ( mNoUserModification != null )
        {
            String val = mNoUserModification.getString();
            attributeType.setUserModifiable( !"TRUE".equalsIgnoreCase( val ) );
        }

        // Usage
        Attribute mUsage = entry.get( MetaSchemaConstants.M_USAGE_AT );

        if ( mUsage != null )
        {
            attributeType.setUsage( UsageEnum.getUsage( mUsage.getString() ) );
        }

        // Common properties
        setSchemaObjectProperties( attributeType, entry, schema );

        return attributeType;
    }


    /**
     * Process the FQCN attribute
     * 
     * @param entry The entry to read
     * @param objectType The type of schema object
     * @return The schema object FQCN
     * @throws LdapInvalidAttributeValueException If the attribute does not contain a valid value
     */
    private String getFqcn( Entry entry, String objectType ) throws LdapInvalidAttributeValueException
    {
        // The FQCN
        Attribute mFqcn = entry.get( MetaSchemaConstants.M_FQCN_AT );

        if ( mFqcn == null )
        {
            String msg = I18n.err( I18n.ERR_16034_ENTRY_WITHOUT_VALID_AT, objectType, MetaSchemaConstants.M_FQCN_AT );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        return mFqcn.getString();
    }


    /**
     * Process the FQCN attribute
     * 
     * @param description The Schema Object description
     * @param objectType The SchemaObject type
     * @return The SchemaObject FQCN
     */
    private String getFqcn( LoadableSchemaObject description, String objectType )
    {
        // The FQCN
        String mFqcn = description.getFqcn();

        if ( mFqcn == null )
        {
            String msg = I18n.err( I18n.ERR_16034_ENTRY_WITHOUT_VALID_AT, objectType, MetaSchemaConstants.M_FQCN_AT );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        return mFqcn;
    }


    /**
     * Process the ByteCode attribute
     * 
     * @param description The SchemaObject description
     * @param objectType The SchemaObject type
     * @return The Attribute containing the byteCode
     */
    private Attribute getByteCode( LoadableSchemaObject description, String objectType )
    {
        String byteCodeString = description.getBytecode();

        if ( byteCodeString == null )
        {
            String msg = I18n.err( I18n.ERR_16034_ENTRY_WITHOUT_VALID_AT, objectType, MetaSchemaConstants.M_BYTECODE_AT );
            
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( msg );
            }
            
            throw new IllegalArgumentException( msg );
        }

        byte[] bytecode = Base64.getDecoder().decode( byteCodeString );
        
        return new DefaultAttribute( MetaSchemaConstants.M_BYTECODE_AT, bytecode );
    }


    /**
     * Process the common attributes to all SchemaObjects :
     *  - obsolete
     *  - description
     *  - names
     *  - schemaName
     *  - specification (if any)
     *  - extensions
     *  - isReadOnly
     *  - isEnabled
     *  
     *  @param schemaObject The SchemaObject to set
     *  @param entry The entry containing the SchemaObject properties
     *  @param schema  the updated Schema 
     * @throws LdapInvalidAttributeValueException If some of the properties are invalid
     */
    private void setSchemaObjectProperties( SchemaObject schemaObject, Entry entry, Schema schema )
        throws LdapInvalidAttributeValueException
    {
        // The isObsolete field
        Attribute mObsolete = entry.get( MetaSchemaConstants.M_OBSOLETE_AT );

        if ( mObsolete != null )
        {
            String val = mObsolete.getString();
            schemaObject.setObsolete( "TRUE".equalsIgnoreCase( val ) );
        }

        // The description field
        Attribute mDescription = entry.get( MetaSchemaConstants.M_DESCRIPTION_AT );

        if ( mDescription != null )
        {
            schemaObject.setDescription( mDescription.getString() );
        }

        // The names field
        Attribute names = entry.get( MetaSchemaConstants.M_NAME_AT );

        if ( names != null )
        {
            List<String> values = new ArrayList<>();

            for ( Value name : names )
            {
                values.add( name.getString() );
            }

            schemaObject.setNames( values );
        }

        // The isEnabled field
        Attribute mDisabled = entry.get( MetaSchemaConstants.M_DISABLED_AT );

        // If the SchemaObject has an explicit m-disabled attribute, then use it.
        // Otherwise, inherit it from the schema
        if ( mDisabled != null )
        {
            String val = mDisabled.getString();
            schemaObject.setEnabled( !"TRUE".equalsIgnoreCase( val ) );
        }
        else
        {
            schemaObject.setEnabled( schema.isEnabled() );
        }

        // The specification field
        /*
         * TODO : create the M_SPECIFICATION_AT
        EntryAttribute mSpecification = entry.get( MetaSchemaConstants.M_SPECIFICATION_AT );
        
        if ( mSpecification != null )
        {
            so.setSpecification( mSpecification.getString() );
        }
        */

        // The schemaName field
        schemaObject.setSchemaName( schema.getSchemaName() );

        // The extensions fields
        // X-SCHEMA
        Attribute xSchema = entry.get( MetaSchemaConstants.X_SCHEMA_AT );

        if ( xSchema != null )
        {
            String schemaName = xSchema.getString();

            if ( !schema.getSchemaName().equalsIgnoreCase( schemaName ) )
            {
                if ( LOG.isWarnEnabled() )
                {
                    LOG.warn( I18n.msg( I18n.MSG_16011_SCHEMA_XSCHEMA_DIFF, schema.getSchemaName(), schemaName, entry ) );
                }
            }

            schemaObject.addExtension( MetaSchemaConstants.X_SCHEMA_AT, schemaName );
        }

        // X-NOT-HUMAN-READABLE
        Attribute xNotHumanReadable = entry.get( MetaSchemaConstants.X_NOT_HUMAN_READABLE_AT );

        if ( xNotHumanReadable != null )
        {
            String value = xNotHumanReadable.getString();

            schemaObject.addExtension( MetaSchemaConstants.X_NOT_HUMAN_READABLE_AT, value );
        }

        // X-READ-ONLY
        Attribute xReadOnly = entry.get( MetaSchemaConstants.X_READ_ONLY_AT );

        if ( xReadOnly != null )
        {
            String value = xReadOnly.getString();

            schemaObject.addExtension( MetaSchemaConstants.X_READ_ONLY_AT, value );
        }
    }


    /**
     * Process the common attributes to all SchemaObjects :
     *  - obsolete
     *  - description
     *  - names
     *  - schemaName
     *  - specification (if any)
     *  - extensions
     *  - isEnabled
     *  
     *  @param schemaObject The SchemaObject to set
     *  @param description The SchemaObjetc description
     *  @param schema  the updated Schema 
     */
    private void setSchemaObjectProperties( SchemaObject schemaObject, SchemaObject description, Schema schema )
    {
        // The isObsolete field
        schemaObject.setObsolete( description.isObsolete() );

        // The description field
        schemaObject.setDescription( description.getDescription() );

        // The names field
        schemaObject.setNames( description.getNames() );

        // The isEnabled field. Has the description does not hold a
        // Disable field, we will inherit from the schema enable field
        schemaObject.setEnabled( schema.isEnabled() );

        // The specification field
        schemaObject.setSpecification( description.getSpecification() );

        // The schemaName field
        schemaObject.setSchemaName( schema.getSchemaName() );

        // The extensions field
        schemaObject.setExtensions( description.getExtensions() );
    }
}
