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
package org.apache.directory.shared.ldap.schema.loader.ldif;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.apache.directory.junit.tools.Concurrent;
import org.apache.directory.junit.tools.ConcurrentJunitRunner;
import org.apache.directory.shared.ldap.exception.LdapUnwillingToPerformException;
import org.apache.directory.shared.ldap.schema.SchemaManager;
import org.apache.directory.shared.ldap.schema.ldif.extractor.SchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.ldif.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.shared.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.shared.ldap.schema.registries.DefaultSchema;
import org.apache.directory.shared.ldap.schema.registries.Schema;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * A test class for SchemaManager load() method. We test those methods here :
 * 
 *  Server API
 *     boolean load( Schema... schemas ) throws Exception
 *     boolean load( String... schemas ) throws Exception
 *     boolean loadDisabled( Schema... schemas ) throws Exception
 *     boolean loadDisabled( String... schemas ) throws Exception
 *     boolean loadAllEnabled() throws Exception
 *
 *  Studio API :
 *     boolean loadRelaxed( Schema... schemas ) throws Exception
 *     boolean loadRelaxed( String... schemas ) throws Exception
 *     boolean loadAllEnabledRelaxed() throws Exception 
 *     
 * We check the resulting number of SchemaObjects in the registries. Those number are :
 * 
 * Apache :
 *   AT :  53
 *   C  :   8
 *   MR :   8
 *   N  :   8
 *   OC :  17
 *   SC :   3
 *   S  :   7
 *   OID:  85
 *   
 * ApacheDns :
 *   AT :  16
 *   OC :  11
 *   OID:  27
 *   
 * ApacheMeta :
 *   AT :  31
 *   C  :   5
 *   MR :   5
 *   N  :   7
 *   OC :  13
 *   SC :   4
 *   S  :   5
 *   OID:  54
 * 
 * AutoFs :
 *   AT :   1
 *   OC :   2
 *   OID:   3
 * 
 * Collective :
 *   AT :  13
 *   OID:  13
 * 
 * Corba :
 *   AT :   2
 *   OC :   3
 *   OID:   5
 * 
 * Core :
 *   AT :  54
 *   OC :  27
 *   OID:  81
 * 
 * Cosine :
 *   AT :  41
 *   OC :  13
 *   OID:  54
 * 
 * Dhcp :
 *   AT :  39
 *   OC :  12
 *   OID:  51
 * 
 * InetOrgPerson :
 *   AT :   9
 *   OC :   1
 *   OID:  10
 * 
 * Java :
 *   AT :   7
 *   OC :   5
 *   OID:  12
 * 
 * Krb5Kdc :
 *   AT :  15
 *   OC :   3
 *   OID:  18
 * 
 * Mozilla :
 *   AT :  17
 *   OC :   1
 *   OID:  18
 * 
 * Nis :
 *   AT :  27
 *   C  :   1
 *   MR :   1
 *   N  :   1
 *   OC :  13
 *   SC :   2
 *   S  :   2
 *   OID:  43
 * 
 * Other :
 *   OID:   0
 * 
 * Samba :
 *   AT :  37
 *   OC :  11
 *   OID:  48
 * 
 * System :
 *   AT :  38
 *   C  :  35
 *   MR :  35
 *   N  :  35
 *   OC :   9
 *   SC :  59
 *   S  :  59
 *   OID: 141
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
//@RunWith(ConcurrentJunitRunner.class)
//@Concurrent()
public class SchemaManagerLoadTest
{
    // A directory in which the ldif files will be stored
    private static String workingDirectory;

    // The schema repository
    private static File schemaRepository;


    @BeforeClass
    public static void setup() throws Exception
    {
        workingDirectory = System.getProperty( "workingDirectory" );

        if ( workingDirectory == null )
        {
            String path = SchemaManagerLoadTest.class.getResource( "" ).getPath();
            int targetPos = path.indexOf( "target" );
            workingDirectory = path.substring( 0, targetPos + 6 );
        }

        schemaRepository = new File( workingDirectory, "schema" );

        // Cleanup the target directory
        FileUtils.deleteDirectory( schemaRepository );

        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( new File( workingDirectory ) );
        extractor.extractOrCopy();
    }


    @AfterClass
    public static void cleanup() throws IOException
    {
        // Cleanup the target directory
        FileUtils.deleteDirectory( schemaRepository );
    }


    /**
     * test loading the "InetOrgPerson", "core" and a disabled schema
     */
    @Test
    public void testLoadCoreInetOrgPersonAndNis() throws Exception
    {
        LdifSchemaLoader loader = new LdifSchemaLoader( schemaRepository );
        SchemaManager schemaManager = new DefaultSchemaManager( loader );
        
        assertTrue( schemaManager.load( "system" ) );
        
        // Try to load a disabled schema when the registries does
        // ot allow disabled schema to be loaded
        assertFalse( schemaManager.load( "core", "nis", "cosine", "InetOrgPerson" ) );

        assertFalse( schemaManager.getErrors().isEmpty() );
        assertEquals( 38, schemaManager.getAttributeTypeRegistry().size() );
        assertEquals( 35, schemaManager.getComparatorRegistry().size() );
        assertEquals( 35, schemaManager.getMatchingRuleRegistry().size() );
        assertEquals( 35, schemaManager.getNormalizerRegistry().size() );
        assertEquals( 9, schemaManager.getObjectClassRegistry().size() );
        assertEquals( 59, schemaManager.getSyntaxCheckerRegistry().size() );
        assertEquals( 59, schemaManager.getLdapSyntaxRegistry().size() );
        assertEquals( 141, schemaManager.getGlobalOidRegistry().size() );

        assertEquals( 1, schemaManager.getRegistries().getLoadedSchemas().size() );
        assertNotNull( schemaManager.getRegistries().getLoadedSchema( "system" ) );
        assertNull( schemaManager.getRegistries().getLoadedSchema( "core" ) );
        assertNull( schemaManager.getRegistries().getLoadedSchema( "cosine" ) );
        assertNull( schemaManager.getRegistries().getLoadedSchema( "InetOrgPerson" ) );
    }

}
