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


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.directory.api.util.FileUtils;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * A test class for SchemaManager enable/disable and loadAllEnbled() methods.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class SchemaManagerEnableDisableLoadTest
{
    // A directory in which the ldif files will be stored
    private static String workingDirectory;

    // The schema repository
    private static File schemaRepository;

    // The schemaManager
    private SchemaManager schemaManager;

    // List of all the available schemas, enabled or disabled
    private List<String> allSchemas = Arrays.asList( "system", "core", "cosine", "inetorgperson", "apache",
        "apachemeta", "collective", "java", "krb5kdc", "other", "nis", "autofs",
        "apachedns", "dhcp", "samba", "corba", "adsconfig", "pwdpolicy" );

    // List of all the enabled schemas
    private List<String> enabledSchemas = Arrays.asList( "system", "core", "cosine", "inetorgperson", "apache",
        "apachemeta", "collective", "java", "krb5kdc", "other", "adsconfig", "pwdpolicy" );

    // List of all the disabled schemas
    @SuppressWarnings("unused")
    private List<String> disabledSchemas = Arrays.asList( "nis", "autofs", "apachedns", "dhcp", "samba", "corba" );


    @BeforeClass
    public static void setup() throws Exception
    {
        workingDirectory = System.getProperty( "workingDirectory" );

        if ( workingDirectory == null )
        {
            String path = SchemaManagerEnableDisableLoadTest.class.getResource( "" ).getPath();
            int targetPos = path.indexOf( "target" );
            workingDirectory = path.substring( 0, targetPos + 6 );
        }

        // Make sure every test class has its own schema directory
        workingDirectory = new File( workingDirectory, "SchemaManagerEnableDisableLoadTest" ).getAbsolutePath();

        schemaRepository = new File( workingDirectory, "schema" );

        // Cleanup the target directory
        FileUtils.deleteDirectory( schemaRepository );

        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( new File( workingDirectory ) );
        extractor.extractOrCopy();
    }


    @Before
    public void init() throws Exception
    {
        LdifSchemaLoader loader = new LdifSchemaLoader( schemaRepository );
        schemaManager = new DefaultSchemaManager( loader );
    }


    @AfterClass
    public static void cleanup() throws IOException
    {
        // Cleanup the target directory
        FileUtils.deleteDirectory( schemaRepository.getParentFile() );
    }


    //-------------------------------------------------------------------------
    // Test the loadAllEnabled() method
    //-------------------------------------------------------------------------
    /**
     * Test the loadEnabled() method
     */
    @Test
    public void testLoadAllEnabled() throws Exception
    {
        assertTrue( schemaManager.getEnabled().isEmpty() );
        assertTrue( schemaManager.loadAllEnabled() );

        for ( String schemaName : allSchemas )
        {
            assertTrue( schemaManager.isSchemaLoaded( schemaName ) );
        }

        // The enabled schemas
        Collection<Schema> enabled = schemaManager.getEnabled();

        assertEquals( enabled.size(), enabledSchemas.size() );

        for ( Schema schema : enabled )
        {
            assertTrue( enabledSchemas.contains( Strings.toLowerCaseAscii( schema.getSchemaName() ) ) );
        }

        // The disabled schemas
        List<Schema> disabled = schemaManager.getDisabled();

        assertEquals( 0, disabled.size() );

        assertTrue( schemaManager.getErrors().isEmpty() );
        assertEquals( 430, schemaManager.getAttributeTypeRegistry().size() );
        assertEquals( 49, schemaManager.getComparatorRegistry().size() );
        assertEquals( 55, schemaManager.getMatchingRuleRegistry().size() );
        assertEquals( 48, schemaManager.getNormalizerRegistry().size() );
        assertEquals( 123, schemaManager.getObjectClassRegistry().size() );
        assertEquals( 68, schemaManager.getSyntaxCheckerRegistry().size() );
        assertEquals( 80, schemaManager.getLdapSyntaxRegistry().size() );
        assertEquals( 688, schemaManager.getGlobalOidRegistry().size() );
        assertEquals( 12, schemaManager.getRegistries().getLoadedSchemas().size() );
        assertNull( schemaManager.getRegistries().getLoadedSchema( "nis" ) );
    }


    //-------------------------------------------------------------------------
    // Test the enable( String... schemaName) method
    //-------------------------------------------------------------------------
    /**
     * Enable a schema which is already enabled
     */
    @Test
    public void testEnableAlreadyEnabled() throws Exception
    {
        schemaManager.loadAllEnabled();

        assertTrue( schemaManager.isEnabled( "core" ) );
        assertTrue( schemaManager.enable( "core" ) );
        assertTrue( schemaManager.isEnabled( "core" ) );
    }


    /**
     * Enable a disabled schema
     */
    @Test
    public void testEnableDisabled() throws Exception
    {
        schemaManager.loadAllEnabled();

        assertTrue( schemaManager.enable( "nis" ) );
        assertTrue( schemaManager.enable( "rfc2307bis" ) );
        assertTrue( schemaManager.isEnabled( "nis" ) );
        assertTrue( schemaManager.isEnabled( "rfc2307bis" ) );

        assertNotNull( schemaManager.lookupAttributeTypeRegistry( "gecos" ) );
        assertNotNull( schemaManager.lookupAttributeTypeRegistry( "automountMapName" ) );

        assertTrue( schemaManager.getErrors().isEmpty() );
        assertEquals( 462, schemaManager.getAttributeTypeRegistry().size() );
        assertEquals( 50, schemaManager.getComparatorRegistry().size() );
        assertEquals( 56, schemaManager.getMatchingRuleRegistry().size() );
        assertEquals( 49, schemaManager.getNormalizerRegistry().size() );
        assertEquals( 139, schemaManager.getObjectClassRegistry().size() );
        assertEquals( 70, schemaManager.getSyntaxCheckerRegistry().size() );
        assertEquals( 82, schemaManager.getLdapSyntaxRegistry().size() );
        assertEquals( 739, schemaManager.getGlobalOidRegistry().size() );

        assertEquals( 14, schemaManager.getRegistries().getLoadedSchemas().size() );
        assertNotNull( schemaManager.getRegistries().getLoadedSchema( "nis" ) );
        assertNotNull( schemaManager.getRegistries().getLoadedSchema( "rfc2307bis" ) );
    }


    /**
     * Disable an enabled schema
     */
    @Test
    public void testDisableEnabled() throws Exception
    {
        schemaManager.loadAllEnabled();

        assertTrue( schemaManager.enable( "nis" ) );
        assertTrue( schemaManager.isEnabled( "nis" ) );

        assertEquals( 13, schemaManager.getRegistries().getLoadedSchemas().size() );

        assertTrue( schemaManager.disable( "nis" ) );

        try
        {
            schemaManager.lookupAttributeTypeRegistry( "gecos" );
            fail();
        }
        catch ( LdapException ne )
        {
            // Expected
        }

        assertTrue( schemaManager.getErrors().isEmpty() );
        assertEquals( 430, schemaManager.getAttributeTypeRegistry().size() );
        assertEquals( 49, schemaManager.getComparatorRegistry().size() );
        assertEquals( 55, schemaManager.getMatchingRuleRegistry().size() );
        assertEquals( 48, schemaManager.getNormalizerRegistry().size() );
        assertEquals( 123, schemaManager.getObjectClassRegistry().size() );
        assertEquals( 68, schemaManager.getSyntaxCheckerRegistry().size() );
        assertEquals( 80, schemaManager.getLdapSyntaxRegistry().size() );
        assertEquals( 688, schemaManager.getGlobalOidRegistry().size() );

        assertEquals( 12, schemaManager.getRegistries().getLoadedSchemas().size() );
        assertNull( schemaManager.getRegistries().getLoadedSchema( "nis" ) );

    }


    @Test
    public void testEnableNonExisting()
    {

    }


    /**
     * Enable multiple schemas, some are enabled, some are disabled, some are not existing
     */
    @Test
    public void testEnableMultipleSchemas()
    {

    }


    /**
     * Enable a disabled schema, which depends on a disabled schema itself.
     * Samba is disabled, and depends on nis which is also disabled. Enabling samba
     * should enabled nis.
     */
    @Test
    public void testEnableDisabledDependingOnDisabled() throws Exception
    {
        schemaManager.loadAllEnabled();

        assertFalse( schemaManager.isEnabled( "samba" ) );
        assertFalse( schemaManager.isEnabled( "nis" ) );

        assertTrue( schemaManager.enable( "samba" ) );
        assertTrue( schemaManager.isEnabled( "samba" ) );
        assertTrue( schemaManager.isEnabled( "nis" ) );

        assertNotNull( schemaManager.lookupAttributeTypeRegistry( "gecos" ) );

        assertTrue( schemaManager.getErrors().isEmpty() );
        assertEquals( 504, schemaManager.getAttributeTypeRegistry().size() );
        assertEquals( 50, schemaManager.getComparatorRegistry().size() );
        assertEquals( 56, schemaManager.getMatchingRuleRegistry().size() );
        assertEquals( 49, schemaManager.getNormalizerRegistry().size() );
        assertEquals( 147, schemaManager.getObjectClassRegistry().size() );
        assertEquals( 70, schemaManager.getSyntaxCheckerRegistry().size() );
        assertEquals( 82, schemaManager.getLdapSyntaxRegistry().size() );
        assertEquals( 789, schemaManager.getGlobalOidRegistry().size() );

        assertEquals( 14, schemaManager.getRegistries().getLoadedSchemas().size() );
        assertNotNull( schemaManager.getRegistries().getLoadedSchema( "samba" ) );
        assertNotNull( schemaManager.getRegistries().getLoadedSchema( "nis" ) );
    }
}
