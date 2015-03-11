/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.ldap.client.api;


import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.AttributesFactory;
import org.apache.directory.api.ldap.model.schema.DitContentRule;
import org.apache.directory.api.ldap.model.schema.DitStructureRule;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MatchingRuleUse;
import org.apache.directory.api.ldap.model.schema.NameForm;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.SchemaObjectWrapper;
import org.apache.directory.api.ldap.model.schema.parsers.AttributeTypeDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.DitContentRuleDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.DitStructureRuleDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescription;
import org.apache.directory.api.ldap.model.schema.parsers.LdapComparatorDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.LdapSyntaxDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.MatchingRuleDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.MatchingRuleUseDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.NameFormDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.NormalizerDescription;
import org.apache.directory.api.ldap.model.schema.parsers.NormalizerDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.ObjectClassDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.parsers.SyntaxCheckerDescription;
import org.apache.directory.api.ldap.model.schema.parsers.SyntaxCheckerDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.registries.AbstractSchemaLoader;
import org.apache.directory.api.ldap.model.schema.registries.DefaultSchema;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.util.Base64;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A schema loader which uses LdapConnection to load schema from a ApacheDS serveur
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DefaultSchemaLoader extends AbstractSchemaLoader
{
    private static final String DEFAULT_APACHEDS_VENDOR_NAME = "Apache Software Foundation";

    /** the logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultSchemaLoader.class );

    /** the connection to the ldap server */
    private LdapConnection connection;

    /** the subschemaSubentry DN */
    private Dn subschemaSubentryDn;

    /** The SubschemaSubentry descriptions parsers */
    private static AttributeTypeDescriptionSchemaParser AT_DESCR_SCHEMA_PARSER = new AttributeTypeDescriptionSchemaParser();
    private static DitStructureRuleDescriptionSchemaParser DSR_DESCR_SCHEMA_PARSER = new DitStructureRuleDescriptionSchemaParser();
    private static DitContentRuleDescriptionSchemaParser DCR_DESCR_SCHEMA_PARSER = new DitContentRuleDescriptionSchemaParser();
    private static MatchingRuleDescriptionSchemaParser MR_DESCR_SCHEMA_PARSER = new MatchingRuleDescriptionSchemaParser();
    private static MatchingRuleUseDescriptionSchemaParser MRU_DESCR_SCHEMA_PARSER = new MatchingRuleUseDescriptionSchemaParser();
    private static NameFormDescriptionSchemaParser NF_DESCR_SCHEMA_PARSER = new NameFormDescriptionSchemaParser();
    private static ObjectClassDescriptionSchemaParser OC_DESCR_SCHEMA_PARSER = new ObjectClassDescriptionSchemaParser();
    private static LdapSyntaxDescriptionSchemaParser LS_DESCR_SCHEMA_PARSER = new LdapSyntaxDescriptionSchemaParser();

    private static LdapComparatorDescriptionSchemaParser C_DESCR_SCHEMA_PARSER = new LdapComparatorDescriptionSchemaParser();
    private static NormalizerDescriptionSchemaParser N_DESCR_SCHEMA_PARSER = new NormalizerDescriptionSchemaParser();
    private static SyntaxCheckerDescriptionSchemaParser SC_DESCR_SCHEMA_PARSER = new SyntaxCheckerDescriptionSchemaParser();


    /**
     * Creates a new instance of DefaultSchemaLoader.
     *
     * @param connection the LDAP connection
     * @throws Exception if the connection is not authenticated or if there are any problems
     *                   while loading the schema entries
     */
    public DefaultSchemaLoader( LdapConnection connection ) throws LdapException
    {
        this( connection, false );
    }


    /**
     * Creates a new instance of DefaultSchemaLoader.
     *
     * @param connection the LDAP connection
     * @param initial setting for the quirks mode
     * @throws Exception if the connection is not authenticated or if there are any problems
     *                   while loading the schema entries
     */
    public DefaultSchemaLoader( LdapConnection connection, boolean quirksMode ) throws LdapException
    {
        if ( connection == null )
        {
            throw new InvalidConnectionException( "Cannot connect on the server, the connection is null" );
        }

        this.connection = connection;
        setQuirksMode( quirksMode );

        // Flagging if the connection was already connected
        boolean wasConnected = connection.isConnected();

        try
        {
            // Connecting (if needed)
            if ( !wasConnected )
            {
                connection.connect();
            }

            // Getting the subschemaSubentry DN from the rootDSE
            Entry rootDse = connection.lookup( Dn.ROOT_DSE, SchemaConstants.SUBSCHEMA_SUBENTRY_AT,
                SchemaConstants.VENDOR_NAME_AT );

            if ( rootDse != null )
            {
                // Checking if this is an ApacheDS server
                if ( isApacheDs( rootDse ) )
                {
                    // Getting the subSchemaSubEntry attribute
                    Attribute subschemaSubentryAttribute = rootDse.get( SchemaConstants.SUBSCHEMA_SUBENTRY_AT );

                    if ( ( subschemaSubentryAttribute != null ) && ( subschemaSubentryAttribute.size() > 0 ) )
                    {
                        subschemaSubentryDn = new Dn( connection.getSchemaManager(),
                            subschemaSubentryAttribute.getString() );

                        loadSchemas();
                    }
                }
                else
                {
                    try
                    {
                        // No matter what, first try to search the schema from the rootDSE
                        // Getting the subSchemaSubEntry attribute
                        Attribute subschemaSubentryAttribute = rootDse.get( SchemaConstants.SUBSCHEMA_SUBENTRY_AT );

                        if ( ( subschemaSubentryAttribute != null ) && ( subschemaSubentryAttribute.size() > 0 ) )
                        {
                            subschemaSubentryDn = new Dn( connection.getSchemaManager(),
                                subschemaSubentryAttribute.getString() );

                            loadSchemas();
                        }
                    }
                    catch ( LdapException le )
                    {
                        // TODO : if we can't read the schema from the rootDSE, just try to read the 
                        // schema from cn=schema
                        throw le;
                    }
                }
            }
        }
        finally
        {
            // Checking if the connection needs to be closed
            if ( ( !wasConnected ) && ( connection.isConnected() ) )
            {
                try
                {
                    connection.close();
                }
                catch ( IOException e )
                {
                    throw new LdapException( e );
                }
            }
        }
    }


    /**
     * Indicates if the given Root DSE corresponds to an ApacheDS server.
     *
     * @param rootDse the Root DSE
     * @return <code>true</code> if this is an ApacheDS server,
     *         <code>false</code> if not.
     * @throws LdapInvalidAttributeValueException
     */
    private boolean isApacheDs( Entry rootDse ) throws LdapInvalidAttributeValueException
    {
        if ( rootDse != null )
        {
            Attribute vendorNameAttribute = rootDse.get( SchemaConstants.VENDOR_NAME_AT );

            if ( ( vendorNameAttribute != null ) && vendorNameAttribute.size() == 1 )
            {
                return DEFAULT_APACHEDS_VENDOR_NAME.equalsIgnoreCase( vendorNameAttribute.getString() );
            }
        }

        return false;
    }


    /**
     * Creates a new instance of NetworkSchemaLoader.
     *
     * @param connection the LDAP connection
     * @throws Exception if the connection is not authenticated or if there are any problems
     *                   while loading the schema entries
     */
    public DefaultSchemaLoader( LdapConnection connection, Dn subschemaSubentryDn ) throws Exception
    {
        if ( !connection.isAuthenticated() )
        {
            throw new IllegalArgumentException( "connection is not authenticated" );
        }

        this.connection = connection;
        this.subschemaSubentryDn = subschemaSubentryDn;

        loadSchemas();
    }


    /**
     * Load all the schemas.
     * 
     * @param subschemaSubentryDn
     * @throws Exception
     */
    private void loadSchemas() throws LdapException
    {
        LOG.debug( "initializing schemas" );

        // Load all the elements from the SubschemaSubentry
        Entry subschemaSubentry = connection.lookup( subschemaSubentryDn,
            SchemaConstants.ATTRIBUTE_TYPES_AT,
            SchemaConstants.COMPARATORS_AT,
            SchemaConstants.DIT_CONTENT_RULES_AT,
            SchemaConstants.DIT_STRUCTURE_RULES_AT,
            SchemaConstants.LDAP_SYNTAXES_AT,
            SchemaConstants.MATCHING_RULES_AT,
            SchemaConstants.MATCHING_RULE_USE_AT,
            SchemaConstants.NAME_FORMS_AT,
            SchemaConstants.NORMALIZERS_AT,
            SchemaConstants.OBJECT_CLASSES_AT,
            SchemaConstants.SYNTAX_CHECKERS_AT
            );

        // Load all the AT
        Attribute attributeTypes = subschemaSubentry.get( SchemaConstants.ATTRIBUTE_TYPES_AT );
        loadAttributeTypes( attributeTypes );

        // Load all the C
        Attribute comparators = subschemaSubentry.get( SchemaConstants.COMPARATORS_AT );
        loadComparators( comparators );

        // Load all the DCR
        Attribute ditContentRules = subschemaSubentry.get( SchemaConstants.DIT_CONTENT_RULES_AT );
        loadDitContentRules( ditContentRules );

        // Load all the DSR
        Attribute ditStructureRules = subschemaSubentry.get( SchemaConstants.DIT_STRUCTURE_RULES_AT );
        loadDitStructureRules( ditStructureRules );

        // Load all the LS
        Attribute ldapSytaxes = subschemaSubentry.get( SchemaConstants.LDAP_SYNTAXES_AT );
        loadLdapSyntaxes( ldapSytaxes );

        // Load all the MR
        Attribute matchingRules = subschemaSubentry.get( SchemaConstants.MATCHING_RULES_AT );
        loadMatchingRules( matchingRules );

        // Load all the MRU
        Attribute matchingRuleUse = subschemaSubentry.get( SchemaConstants.MATCHING_RULE_USE_AT );
        loadMatchingRuleUses( matchingRuleUse );

        // Load all the N
        Attribute normalizers = subschemaSubentry.get( SchemaConstants.NORMALIZERS_AT );
        loadNormalizers( normalizers );

        // Load all the NF
        Attribute nameForms = subschemaSubentry.get( SchemaConstants.NAME_FORMS_AT );
        loadNameForms( nameForms );

        // Load all the OC
        Attribute objectClasses = subschemaSubentry.get( SchemaConstants.OBJECT_CLASSES_AT );
        loadObjectClasses( objectClasses );

        // Load all the SC
        Attribute syntaxCheckers = subschemaSubentry.get( SchemaConstants.SYNTAX_CHECKERS_AT );
        loadSyntaxCheckers( syntaxCheckers );
    }


    /**
     * {@inheritDoc}
     */
    private void loadAttributeTypes( Attribute attributeTypes ) throws LdapException
    {
        if ( attributeTypes == null )
        {
            return;
        }

        for ( Value<?> value : attributeTypes )
        {
            String desc = value.getString();

            try
            {
                AttributeType attributeType = AT_DESCR_SCHEMA_PARSER.parseAttributeTypeDescription( desc );

                updateSchemas( attributeType );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadComparators( Attribute comparators ) throws LdapException
    {
        if ( comparators == null )
        {
            return;
        }

        for ( Value<?> value : comparators )
        {
            String desc = value.getString();

            try
            {
                LdapComparatorDescription comparator = C_DESCR_SCHEMA_PARSER.parseComparatorDescription( desc );

                updateSchemas( comparator );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadDitContentRules( Attribute ditContentRules ) throws LdapException
    {
        if ( ditContentRules == null )
        {
            return;
        }

        for ( Value<?> value : ditContentRules )
        {
            String desc = value.getString();

            try
            {
                DitContentRule ditContentRule = DCR_DESCR_SCHEMA_PARSER.parseDITContentRuleDescription( desc );

                updateSchemas( ditContentRule );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadDitStructureRules( Attribute ditStructureRules ) throws LdapException
    {
        if ( ditStructureRules == null )
        {
            return;
        }

        for ( Value<?> value : ditStructureRules )
        {
            String desc = value.getString();

            try
            {
                DitStructureRule ditStructureRule = DSR_DESCR_SCHEMA_PARSER.parseDITStructureRuleDescription( desc );

                updateSchemas( ditStructureRule );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadLdapSyntaxes( Attribute ldapSyntaxes ) throws LdapException
    {
        if ( ldapSyntaxes == null )
        {
            return;
        }

        for ( Value<?> value : ldapSyntaxes )
        {
            String desc = value.getString();

            try
            {
                LdapSyntax ldapSyntax = LS_DESCR_SCHEMA_PARSER.parseLdapSyntaxDescription( desc );

                updateSchemas( ldapSyntax );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadMatchingRules( Attribute matchingRules ) throws LdapException
    {
        if ( matchingRules == null )
        {
            return;
        }

        for ( Value<?> value : matchingRules )
        {
            String desc = value.getString();

            try
            {
                MatchingRule matchingRule = MR_DESCR_SCHEMA_PARSER.parseMatchingRuleDescription( desc );

                updateSchemas( matchingRule );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadMatchingRuleUses( Attribute matchingRuleUses ) throws LdapException
    {
        if ( matchingRuleUses == null )
        {
            return;
        }

        for ( Value<?> value : matchingRuleUses )
        {
            String desc = value.getString();

            try
            {
                MatchingRuleUse matchingRuleUse = MRU_DESCR_SCHEMA_PARSER.parseMatchingRuleUseDescription( desc );

                updateSchemas( matchingRuleUse );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadNameForms( Attribute nameForms ) throws LdapException
    {
        if ( nameForms == null )
        {
            return;
        }

        for ( Value<?> value : nameForms )
        {
            String desc = value.getString();

            try
            {
                NameForm nameForm = NF_DESCR_SCHEMA_PARSER.parseNameFormDescription( desc );

                updateSchemas( nameForm );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadNormalizers( Attribute normalizers ) throws LdapException
    {
        if ( normalizers == null )
        {
            return;
        }

        for ( Value<?> value : normalizers )
        {
            String desc = value.getString();

            try
            {
                NormalizerDescription normalizer = N_DESCR_SCHEMA_PARSER.parseNormalizerDescription( desc );

                updateSchemas( normalizer );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadObjectClasses( Attribute objectClasses ) throws LdapException
    {
        if ( objectClasses == null )
        {
            return;
        }

        for ( Value<?> value : objectClasses )
        {
            String desc = value.getString();

            try
            {
                ObjectClass objectClass = OC_DESCR_SCHEMA_PARSER.parseObjectClassDescription( desc );

                updateSchemas( objectClass );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    /**
     * {@inheritDoc}
     */
    private void loadSyntaxCheckers( Attribute syntaxCheckers ) throws LdapException
    {
        if ( syntaxCheckers == null )
        {
            return;
        }

        for ( Value<?> value : syntaxCheckers )
        {
            String desc = value.getString();

            try
            {
                SyntaxCheckerDescription syntaxChecker = SC_DESCR_SCHEMA_PARSER.parseSyntaxCheckerDescription( desc );

                updateSchemas( syntaxChecker );
            }
            catch ( ParseException pe )
            {
                throw new LdapException( pe );
            }
        }
    }


    private void updateSchemas( SchemaObject schemaObject )
    {
        String schemaName = schemaObject.getSchemaName();
        Schema schema = null;

        if ( Strings.isEmpty( schemaName ) || Strings.equals( "null", schemaName ) )
        {
            schemaName = "default";
            schema = schemaMap.get( schemaName );
        }
        else
        {
            schema = schemaMap.get( schemaName );
        }

        if ( schema == null )
        {
            schema = new DefaultSchema( schemaName );

            schemaMap.put( schemaName, schema );
        }

        schema.getContent().add( new SchemaObjectWrapper( schemaObject ) );

    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadAttributeTypes( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> attributeTypeEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return attributeTypeEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof AttributeType )
                {
                    AttributeType attributeType = ( AttributeType ) schemaObject;

                    Entry attributeTypeEntry = factory.convert( attributeType, schema, null );

                    attributeTypeEntries.add( attributeTypeEntry );
                }
            }
        }

        return attributeTypeEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadComparators( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> comparatorEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return comparatorEntries;
        }

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof LdapComparatorDescription )
                {
                    LdapComparatorDescription ldapComparatorDescription = ( LdapComparatorDescription ) schemaObject;
                    Entry lcEntry = getEntry( ldapComparatorDescription );

                    comparatorEntries.add( lcEntry );
                }
            }
        }

        return comparatorEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadDitContentRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> ditContentRuleEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return ditContentRuleEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof DitContentRule )
                {
                    DitContentRule ditContentRule = ( DitContentRule ) schemaObject;

                    Entry ditContentRuleEntry = factory.convert( ditContentRule, schema, null );

                    ditContentRuleEntries.add( ditContentRuleEntry );
                }
            }
        }

        return ditContentRuleEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadDitStructureRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> ditStructureRuleEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return ditStructureRuleEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof DitStructureRule )
                {
                    DitStructureRule ditStructureRule = ( DitStructureRule ) schemaObject;

                    Entry ditStructureRuleEntry = factory.convert( ditStructureRule, schema, null );

                    ditStructureRuleEntries.add( ditStructureRuleEntry );
                }
            }
        }

        return ditStructureRuleEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadMatchingRuleUses( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> matchingRuleUseEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return matchingRuleUseEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof MatchingRuleUse )
                {
                    MatchingRuleUse matchingRuleUse = ( MatchingRuleUse ) schemaObject;

                    Entry matchingRuleUseEntry = factory.convert( matchingRuleUse, schema, null );

                    matchingRuleUseEntries.add( matchingRuleUseEntry );
                }
            }
        }

        return matchingRuleUseEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadMatchingRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> matchingRuleEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return matchingRuleEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof MatchingRule )
                {
                    MatchingRule matchingRule = ( MatchingRule ) schemaObject;

                    Entry matchingRuleEntry = factory.convert( matchingRule, schema, null );

                    matchingRuleEntries.add( matchingRuleEntry );
                }
            }
        }

        return matchingRuleEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadNameForms( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> nameFormEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return nameFormEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof NameForm )
                {
                    NameForm nameForm = ( NameForm ) schemaObject;

                    Entry nameFormEntry = factory.convert( nameForm, schema, null );

                    nameFormEntries.add( nameFormEntry );
                }
            }
        }

        return nameFormEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadNormalizers( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> normalizerEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return normalizerEntries;
        }

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof NormalizerDescription )
                {
                    NormalizerDescription normalizerDescription = ( NormalizerDescription ) schemaObject;
                    Entry normalizerEntry = getEntry( normalizerDescription );

                    normalizerEntries.add( normalizerEntry );
                }
            }
        }

        return normalizerEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadObjectClasses( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> objectClassEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return objectClassEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof ObjectClass )
                {
                    ObjectClass objectClass = ( ObjectClass ) schemaObject;

                    Entry objectClassEntry = factory.convert( objectClass, schema, null );

                    objectClassEntries.add( objectClassEntry );
                }
            }
        }

        return objectClassEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadSyntaxCheckers( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> syntaxCheckerEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return syntaxCheckerEntries;
        }

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof SyntaxCheckerDescription )
                {
                    SyntaxCheckerDescription syntaxCheckerDescription = ( SyntaxCheckerDescription ) schemaObject;
                    Entry syntaxCheckerEntry = getEntry( syntaxCheckerDescription );

                    syntaxCheckerEntries.add( syntaxCheckerEntry );
                }
            }
        }

        return syntaxCheckerEntries;
    }


    /**
     * {@inheritDoc}
     */
    public List<Entry> loadSyntaxes( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> syntaxEntries = new ArrayList<Entry>();

        if ( schemas == null )
        {
            return syntaxEntries;
        }

        AttributesFactory factory = new AttributesFactory();

        for ( Schema schema : schemas )
        {
            Set<SchemaObjectWrapper> schemaObjectWrappers = schema.getContent();

            for ( SchemaObjectWrapper schemaObjectWrapper : schemaObjectWrappers )
            {
                SchemaObject schemaObject = schemaObjectWrapper.get();

                if ( schemaObject instanceof LdapSyntax )
                {
                    LdapSyntax ldapSyntax = ( LdapSyntax ) schemaObject;

                    Entry ldapSyntaxEntry = factory.convert( ldapSyntax, schema, null );

                    syntaxEntries.add( ldapSyntaxEntry );
                }
            }
        }

        return syntaxEntries;
    }


    private Entry getEntry( LdapComparatorDescription comparatorDescription )
    {
        Entry entry = new DefaultEntry();

        entry.put( SchemaConstants.OBJECT_CLASS_AT,
            SchemaConstants.TOP_OC,
            MetaSchemaConstants.META_TOP_OC,
            MetaSchemaConstants.META_COMPARATOR_OC );

        entry.put( MetaSchemaConstants.M_OID_AT, comparatorDescription.getOid() );
        entry.put( MetaSchemaConstants.M_FQCN_AT, comparatorDescription.getFqcn() );

        if ( comparatorDescription.getBytecode() != null )
        {
            entry.put( MetaSchemaConstants.M_BYTECODE_AT,
                Base64.decode( comparatorDescription.getBytecode().toCharArray() ) );
        }

        if ( comparatorDescription.getDescription() != null )
        {
            entry.put( MetaSchemaConstants.M_DESCRIPTION_AT, comparatorDescription.getDescription() );
        }

        return entry;
    }


    private Entry getEntry( SyntaxCheckerDescription syntaxCheckerDescription )
    {
        Entry entry = new DefaultEntry();

        entry.put( SchemaConstants.OBJECT_CLASS_AT,
            SchemaConstants.TOP_OC,
            MetaSchemaConstants.META_TOP_OC,
            MetaSchemaConstants.META_SYNTAX_CHECKER_OC );

        entry.put( MetaSchemaConstants.M_OID_AT, syntaxCheckerDescription.getOid() );
        entry.put( MetaSchemaConstants.M_FQCN_AT, syntaxCheckerDescription.getFqcn() );

        if ( syntaxCheckerDescription.getBytecode() != null )
        {
            entry.put( MetaSchemaConstants.M_BYTECODE_AT,
                Base64.decode( syntaxCheckerDescription.getBytecode().toCharArray() ) );
        }

        if ( syntaxCheckerDescription.getDescription() != null )
        {
            entry.put( MetaSchemaConstants.M_DESCRIPTION_AT, syntaxCheckerDescription.getDescription() );
        }

        return entry;
    }


    private Entry getEntry( NormalizerDescription normalizerDescription )
    {
        Entry entry = new DefaultEntry();

        entry.put( SchemaConstants.OBJECT_CLASS_AT,
            SchemaConstants.TOP_OC,
            MetaSchemaConstants.META_TOP_OC,
            MetaSchemaConstants.META_NORMALIZER_OC );

        entry.put( MetaSchemaConstants.M_OID_AT, normalizerDescription.getOid() );
        entry.put( MetaSchemaConstants.M_FQCN_AT, normalizerDescription.getFqcn() );

        if ( normalizerDescription.getBytecode() != null )
        {
            entry.put( MetaSchemaConstants.M_BYTECODE_AT,
                Base64.decode( normalizerDescription.getBytecode().toCharArray() ) );
        }

        if ( normalizerDescription.getDescription() != null )
        {
            entry.put( MetaSchemaConstants.M_DESCRIPTION_AT, normalizerDescription.getDescription() );
        }

        return entry;
    }


    /**
     * Sets the quirks mode for all the internal parsers.
     *
     * If enabled the parser accepts non-numeric OIDs and some
     * special characters in descriptions.
     *
     * @param enabled the new quirks mode
     */
    public void setQuirksMode( boolean enabled )
    {
        AT_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        C_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        DCR_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        DSR_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        LS_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        MR_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        MRU_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        N_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        NF_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        OC_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
        SC_DESCR_SCHEMA_PARSER.setQuirksMode( enabled );
    }
}
