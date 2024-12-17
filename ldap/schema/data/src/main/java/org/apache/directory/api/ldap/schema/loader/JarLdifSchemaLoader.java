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


import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.registries.AbstractSchemaLoader;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.ResourceMap;
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
public class JarLdifSchemaLoader extends AbstractSchemaLoader
{
    /**
     * Filesystem path separator pattern, either forward slash or backslash.
     * java.util.regex.Pattern is immutable so only one instance is needed for all uses.
     */
    private static final String SEPARATOR_PATTERN = "[/\\Q\\\\E]";

    /** ldif file extension used */
    private static final String LDIF_EXT = "ldif";

    /** static class logger */
    private static final Logger LOG = LoggerFactory.getLogger( JarLdifSchemaLoader.class );

    /** a map of all the resources in this jar */
    private static final Map<String, Boolean> RESOURCE_MAP = ResourceMap.getResources( Pattern
        .compile( "schema" + SEPARATOR_PATTERN + "ou=schema.*" ) );

    private final boolean allowDuplicateResources;

    /**
     * Creates a new LDIF based SchemaLoader. The constructor checks to make
     * sure the supplied base directory exists and contains a schema.ldif file
     * and if not complains about it.
     *
     * @throws LdapException if the base directory does not exist or does not
     * a valid schema.ldif file
     * @throws IOException If we can't load the schema
     */
    public JarLdifSchemaLoader() throws IOException, LdapException
    {
        this.allowDuplicateResources = false;
        initializeSchemas();
    }

    /**
     * Creates a new LDIF based SchemaLoader. The constructor checks to make
     * sure the supplied base directory exists and contains a schema.ldif file
     * and if not complains about it.
     *
     * @param allowDuplicateResources If set to true, loading duplicate resources is allowed.
     * E.g. loading schema definitions that are loaded several times on the classpath.
     * In case of several files with the same name, it returns any of them.
     * This is useful in cases when the same artefacts are loaded several times, e.g. in some testing scenarios
     * or weird classloading situations.
     *
     * @throws LdapException if the base directory does not exist or does not
     * a valid schema.ldif file
     * @throws IOException If we can't load the schema
     */
    public JarLdifSchemaLoader( boolean allowDuplicateResources ) throws IOException, LdapException
    {
        this.allowDuplicateResources = allowDuplicateResources;
        initializeSchemas();
    }

    /**
     * Returns true, if loading duplicate resources is allowed.
     * E.g. loading schema definitions that are loaded several times on the classpath.
     * In case of several files with the same name, it returns any of them.
     * This is useful in cases when the same artefacts are loaded several times, e.g. in some testing scenarios
     * or weird classloading situations.
     * 
     * @return <code>true</code>if loading duplicate resources is allowed.
     */
    public boolean isAllowDuplicateResources()
    {
        return allowDuplicateResources;
    }


    private URL getResource( String resource, String msg ) throws IOException
    {
        if ( RESOURCE_MAP.get( resource ) )
        {
            if ( allowDuplicateResources )
            {
                return DefaultSchemaLdifExtractor.getAnyResource( resource, msg );
            }
            else
            {
                return DefaultSchemaLdifExtractor.getUniqueResource( resource, msg );
            }
        }
        else
        {
            return new File( resource ).toURI().toURL();
        }
    }


    /**
     * Scans for LDIF files just describing the various schema contained in
     * the schema repository.
     *
     * @throws LdapException If the schema can't be initialized
     * @throws IOException If the file cannot be read
     */
    private void initializeSchemas() throws IOException, LdapException
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_16006_INITIALIZING_SCHEMA ) );
        }

        Pattern pat = Pattern.compile( "schema" + SEPARATOR_PATTERN + "ou=schema"
            + SEPARATOR_PATTERN + "cn=[a-z0-9-_]*\\." + LDIF_EXT );

        for ( String file : RESOURCE_MAP.keySet() )
        {
            if ( pat.matcher( file ).matches() )
            {
                URL resource = getResource( file, "schema LDIF file" );

                try ( InputStream in = resource.openStream() )
                {
                    try ( LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        Schema schema = getSchema( entry.getEntry() );
                        schemaMap.put( schema.getSchemaName(), schema );
    
                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.msg( I18n.MSG_16007_SCHEMA_INITIALIZED, schema ) );
                        }
                    }
                }
                catch ( LdapException le )
                {
                    LOG.error( I18n.err( I18n.ERR_16009_LDIF_LOAD_FAIL, file ), le );
                    throw le;
                }
            }
        }
    }


    /**
     * Utility method to get a regex.Pattern fragment for the path for a schema directory.
     *
     * @param schema the schema to get the path for
     * @return the regex.Pattern fragment for the path for the specified schema directory
     */
    private String getSchemaDirectoryString( Schema schema )
    {
        return "schema" + "/" + "ou=schema" + "/"
            + "cn=" + Strings.lowerCase( schema.getSchemaName() ) + "/";
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.COMPARATORS_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "comparator LDIF file" );
                    
                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
    
                        comparatorList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.SYNTAX_CHECKERS_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "syntaxChecker LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        syntaxCheckerList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.NORMALIZERS_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "normalizer LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        normalizerList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.MATCHING_RULES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "matchingRules LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        matchingRuleList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.SYNTAXES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "syntax LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        syntaxList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.ATTRIBUTE_TYPES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            // get list of attributeType LDIF schema files in attributeTypes
            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "attributeType LDIF file" );
                    
                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        attributeTypeList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.MATCHING_RULE_USE_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "matchingRuleUse LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        matchingRuleUseList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.NAME_FORMS_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "nameForm LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        nameFormList.add( entry.getEntry() );
                    }
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
        List<Entry> ditContentRulesList = new ArrayList<>();

        if ( schemas == null )
        {
            return ditContentRulesList;
        }

        for ( Schema schema : schemas )
        {
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.DIT_CONTENT_RULES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "ditContentRule LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        ditContentRulesList.add( entry.getEntry() );
                    }
                }
            }
        }

        return ditContentRulesList;
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.DIT_STRUCTURE_RULES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "ditStructureRule LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                       ditStructureRuleList.add( entry.getEntry() );
                    }
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
            String start = getSchemaDirectoryString( schema )
                + SchemaConstants.OBJECT_CLASSES_PATH + "/" + "m-oid=";
            String end = "." + LDIF_EXT;

            for ( String resourcePath : RESOURCE_MAP.keySet() )
            {
                if ( resourcePath.startsWith( start ) && resourcePath.endsWith( end ) )
                {
                    URL resource = getResource( resourcePath, "objectClass LDIF file" );

                    try ( InputStream in = resource.openStream();
                        LdifReader reader = new LdifReader( in ) )
                    {
                        LdifEntry entry = reader.next();
                        objectClassList.add( entry.getEntry() );
                    }
                }
            }
        }

        return objectClassList;
    }
}
