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
package org.apache.directory.api.ldap.schema.loader;


import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.registries.AbstractSchemaLoader;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Loads schema data from LDIF files containing entries representing schema
 * objects, using the meta schema format.
 *
 * This class is used only for tests.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifSchemaLoader extends AbstractSchemaLoader
{
    /** ldif file extension used */
    private static final String LDIF_EXT = "ldif";

    /** ou=schema LDIF file name */
    private static final String OU_SCHEMA_LDIF = "ou=schema." + LDIF_EXT;

    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( LdifSchemaLoader.class );

    /** Speedup for DEBUG mode */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** directory containing the schema LDIF file for ou=schema */
    private final File baseDirectory;

    /** a filter for listing all the LDIF files within a directory */
    private final FilenameFilter ldifFilter = new FilenameFilter()
    {
        @Override
        public boolean accept( File file, String name )
        {
            return name.endsWith( LDIF_EXT );
        }
    };


    /**
     * Creates a new LDIF based SchemaLoader. The constructor checks to make
     * sure the supplied base directory exists and contains a schema.ldif file
     * and if not complains about it.
     *
     * @param baseDirectory the schema LDIF base directory
     * @throws LdapException if the base directory does not exist or does not
     * a valid schema.ldif file
     * @throws IOException If we can't load the schema
     */
    public LdifSchemaLoader( File baseDirectory ) throws LdapException, IOException
    {
        this.baseDirectory = baseDirectory;

        if ( !baseDirectory.exists() )
        {
            String msg = "Provided baseDirectory '" + baseDirectory.getAbsolutePath() + "' does not exist.";
            LOG.error( msg );
            throw new IllegalArgumentException( msg );
        }

        File schemaLdif = new File( baseDirectory, OU_SCHEMA_LDIF );

        if ( !schemaLdif.exists() )
        {
            String msg = I18n.err( I18n.ERR_10004, schemaLdif.getAbsolutePath() );
            LOG.error( msg );
            throw new FileNotFoundException( msg );
        }

        if ( IS_DEBUG )
        {
            LOG.debug( "Using '{}' as the base schema load directory.", baseDirectory );
        }

        initializeSchemas();
    }


    /**
     * Scans for LDIF files just describing the various schema contained in
     * the schema repository.
     *
     * @throws LdapException
     */
    private void initializeSchemas() throws LdapException, IOException
    {
        if ( IS_DEBUG )
        {
            LOG.debug( "Initializing schema" );
        }

        File schemaDirectory = new File( baseDirectory, SchemaConstants.OU_SCHEMA );
        String[] ldifFiles = schemaDirectory.list( ldifFilter );

        if ( ldifFiles != null )
        {
            for ( String ldifFile : ldifFiles )
            {
                File file = new File( schemaDirectory, ldifFile );

                try ( LdifReader reader = new LdifReader( file ) )
                {
                    LdifEntry entry = reader.next();
                    Schema schema = getSchema( entry.getEntry() );

                    if ( schema == null )
                    {
                        // The entry was not a schema, skip it
                        continue;
                    }

                    schemaMap.put( schema.getSchemaName(), schema );

                    if ( IS_DEBUG )
                    {
                        LOG.debug( "Schema Initialized ... \n{}", schema );
                    }
                }
                catch ( LdapException e )
                {
                    LOG.error( I18n.err( I18n.ERR_10003, ldifFile ), e );
                    throw e;
                }
            }
        }
    }


    /**
     * Utility method to get the file for a schema directory.
     *
     * @param schema the schema to get the file for
     * @return the file for the specific schema directory
     */
    private File getSchemaDirectory( Schema schema )
    {
        return new File( new File( baseDirectory, SchemaConstants.OU_SCHEMA ), "cn="
            + Strings.lowerCase( schema.getSchemaName() ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadComparators( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> comparatorList = new ArrayList<>();

        if ( schemas == null )
        {
            return comparatorList;
        }

        for ( Schema schema : schemas )
        {
            File comparatorsDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.COMPARATORS_PATH );

            if ( !comparatorsDirectory.exists() )
            {
                return comparatorList;
            }

            File[] comparators = comparatorsDirectory.listFiles( ldifFilter );

            if ( comparators != null )
            {
                for ( File ldifFile : comparators )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    comparatorList.add( entry.getEntry() );
                }
            }
        }

        return comparatorList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadSyntaxCheckers( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> syntaxCheckerList = new ArrayList<>();

        if ( schemas == null )
        {
            return syntaxCheckerList;
        }

        for ( Schema schema : schemas )
        {
            File syntaxCheckersDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.SYNTAX_CHECKERS_PATH );

            if ( !syntaxCheckersDirectory.exists() )
            {
                return syntaxCheckerList;
            }

            File[] syntaxCheckerFiles = syntaxCheckersDirectory.listFiles( ldifFilter );

            if ( syntaxCheckerFiles != null )
            {
                for ( File ldifFile : syntaxCheckerFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    syntaxCheckerList.add( entry.getEntry() );
                }
            }
        }

        return syntaxCheckerList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadNormalizers( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> normalizerList = new ArrayList<>();

        if ( schemas == null )
        {
            return normalizerList;
        }

        for ( Schema schema : schemas )
        {
            File normalizersDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.NORMALIZERS_PATH );

            if ( !normalizersDirectory.exists() )
            {
                return normalizerList;
            }

            File[] normalizerFiles = normalizersDirectory.listFiles( ldifFilter );

            if ( normalizerFiles != null )
            {
                for ( File ldifFile : normalizerFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    normalizerList.add( entry.getEntry() );
                }
            }
        }

        return normalizerList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadMatchingRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> matchingRuleList = new ArrayList<>();

        if ( schemas == null )
        {
            return matchingRuleList;
        }

        for ( Schema schema : schemas )
        {
            File matchingRulesDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.MATCHING_RULES_PATH );

            if ( !matchingRulesDirectory.exists() )
            {
                return matchingRuleList;
            }

            File[] matchingRuleFiles = matchingRulesDirectory.listFiles( ldifFilter );

            if ( matchingRuleFiles != null )
            {
                for ( File ldifFile : matchingRuleFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    matchingRuleList.add( entry.getEntry() );
                }
            }
        }

        return matchingRuleList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadSyntaxes( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> syntaxList = new ArrayList<>();

        if ( schemas == null )
        {
            return syntaxList;
        }

        for ( Schema schema : schemas )
        {
            File syntaxesDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.SYNTAXES_PATH );

            if ( !syntaxesDirectory.exists() )
            {
                return syntaxList;
            }

            File[] syntaxFiles = syntaxesDirectory.listFiles( ldifFilter );

            if ( syntaxFiles != null )
            {
                for ( File ldifFile : syntaxFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    syntaxList.add( entry.getEntry() );
                }
            }
        }

        return syntaxList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadAttributeTypes( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> attributeTypeList = new ArrayList<>();

        if ( schemas == null )
        {
            return attributeTypeList;
        }

        for ( Schema schema : schemas )
        {
            // check that the attributeTypes directory exists for the schema
            File attributeTypesDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.ATTRIBUTE_TYPES_PATH );

            if ( !attributeTypesDirectory.exists() )
            {
                return attributeTypeList;
            }

            // get list of attributeType LDIF schema files in attributeTypes
            File[] attributeTypeFiles = attributeTypesDirectory.listFiles( ldifFilter );

            if ( attributeTypeFiles != null )
            {
                for ( File ldifFile : attributeTypeFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    attributeTypeList.add( entry.getEntry() );
                }
            }
        }

        return attributeTypeList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadMatchingRuleUses( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> matchingRuleUseList = new ArrayList<>();

        if ( schemas == null )
        {
            return matchingRuleUseList;
        }

        for ( Schema schema : schemas )
        {
            File matchingRuleUsesDirectory = new File( getSchemaDirectory( schema ),
                SchemaConstants.MATCHING_RULE_USE_PATH );

            if ( !matchingRuleUsesDirectory.exists() )
            {
                return matchingRuleUseList;
            }

            File[] matchingRuleUseFiles = matchingRuleUsesDirectory.listFiles( ldifFilter );

            if ( matchingRuleUseFiles != null )
            {
                for ( File ldifFile : matchingRuleUseFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    matchingRuleUseList.add( entry.getEntry() );
                }
            }
        }

        return matchingRuleUseList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadNameForms( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> nameFormList = new ArrayList<>();

        if ( schemas == null )
        {
            return nameFormList;
        }

        for ( Schema schema : schemas )
        {
            File nameFormsDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.NAME_FORMS_PATH );

            if ( !nameFormsDirectory.exists() )
            {
                return nameFormList;
            }

            File[] nameFormFiles = nameFormsDirectory.listFiles( ldifFilter );

            if ( nameFormFiles != null )
            {
                for ( File ldifFile : nameFormFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    nameFormList.add( entry.getEntry() );
                }
            }
        }

        return nameFormList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadDitContentRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> ditContentRuleList = new ArrayList<>();

        if ( schemas == null )
        {
            return ditContentRuleList;
        }

        for ( Schema schema : schemas )
        {
            File ditContentRulesDirectory = new File( getSchemaDirectory( schema ),
                SchemaConstants.DIT_CONTENT_RULES_PATH );

            if ( !ditContentRulesDirectory.exists() )
            {
                return ditContentRuleList;
            }

            File[] ditContentRuleFiles = ditContentRulesDirectory.listFiles( ldifFilter );

            if ( ditContentRuleFiles != null )
            {
                for ( File ldifFile : ditContentRuleFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    ditContentRuleList.add( entry.getEntry() );
                }
            }
        }

        return ditContentRuleList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadDitStructureRules( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> ditStructureRuleList = new ArrayList<>();

        if ( schemas == null )
        {
            return ditStructureRuleList;
        }

        for ( Schema schema : schemas )
        {
            File ditStructureRulesDirectory = new File( getSchemaDirectory( schema ),
                SchemaConstants.DIT_STRUCTURE_RULES_PATH );

            if ( !ditStructureRulesDirectory.exists() )
            {
                return ditStructureRuleList;
            }

            File[] ditStructureRuleFiles = ditStructureRulesDirectory.listFiles( ldifFilter );

            if ( ditStructureRuleFiles != null )
            {
                for ( File ldifFile : ditStructureRuleFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    ditStructureRuleList.add( entry.getEntry() );
                }
            }
        }

        return ditStructureRuleList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Entry> loadObjectClasses( Schema... schemas ) throws LdapException, IOException
    {
        List<Entry> objectClassList = new ArrayList<>();

        if ( schemas == null )
        {
            return objectClassList;
        }

        for ( Schema schema : schemas )
        {
            // get objectClasses directory, check if exists, return if not
            File objectClassesDirectory = new File( getSchemaDirectory( schema ), SchemaConstants.OBJECT_CLASSES_PATH );

            if ( !objectClassesDirectory.exists() )
            {
                return objectClassList;
            }

            // get list of objectClass LDIF files from directory and load
            File[] objectClassFiles = objectClassesDirectory.listFiles( ldifFilter );

            if ( objectClassFiles != null )
            {
                for ( File ldifFile : objectClassFiles )
                {
                    LdifReader reader = new LdifReader( ldifFile );
                    LdifEntry entry = reader.next();
                    reader.close();

                    objectClassList.add( entry.getEntry() );
                }
            }
        }

        return objectClassList;
    }
}
