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
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Multi-threaded 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class MultiThreadedTest
{
    private static Dn referenceDn;
    private static Dn sharedDn;
    private static Rdn referenceRdn;
    private static Rdn sharedRdn;
    private static Ava referenceAva;
    private static Ava sharedAva;

    private static SchemaManager schemaManager;


    @BeforeAll
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();

        referenceDn = new Dn( schemaManager, "dc=example,dc=com" );
        sharedDn = new Dn( schemaManager, "dc=example,dc=com" );

        referenceRdn = new Rdn( schemaManager, "ou=system" );
        sharedRdn = new Rdn( schemaManager, "ou=system" );

        referenceAva = new Ava( schemaManager, "ou", "System" );
        sharedAva = new Ava( schemaManager, "ou", "System" );
    }


    @Test
    public void testNormalize() throws Exception
    {
        Rdn SchemaAwareSharedRdn = new Rdn( schemaManager, sharedRdn );

        assertTrue( SchemaAwareSharedRdn.isSchemaAware() );

        Dn schemaAwareSharedDn = new Dn( schemaManager, sharedDn );
        assertTrue( schemaAwareSharedDn.isSchemaAware() );
    }


    @Test
    public void testNormalizeHashCode() throws Exception
    {
        assertEquals( referenceAva.hashCode(), sharedAva.hashCode() );

        Rdn SchemaAwareSharedRdn = new Rdn( schemaManager, sharedRdn );
        assertEquals( referenceRdn.hashCode(), SchemaAwareSharedRdn.hashCode() );

        Dn schemaAwareSharedDn = new Dn( schemaManager, sharedDn );
        assertEquals( referenceDn.hashCode(), schemaAwareSharedDn.hashCode() );
    }


    @Test
    public void testNormalizeEquals() throws Exception
    {
        assertEquals( referenceAva, sharedAva );
        assertTrue( referenceAva.equals( sharedAva ) );
        assertTrue( sharedAva.equals( referenceAva ) );

        Rdn SchemaAwareSharedRdn = new Rdn( schemaManager, sharedRdn );
        assertEquals( referenceRdn, SchemaAwareSharedRdn );
        assertTrue( referenceRdn.equals( SchemaAwareSharedRdn ) );
        assertTrue( SchemaAwareSharedRdn.equals( referenceRdn ) );

        Dn schemaAwareSharedDn = new Dn( schemaManager, sharedDn );
        assertEquals( referenceDn, schemaAwareSharedDn );
        assertTrue( referenceDn.equals( schemaAwareSharedDn ) );
        assertTrue( schemaAwareSharedDn.equals( referenceDn ) );
    }


    @Test
    public void testNormalizeCompare() throws Exception
    {
        assertTrue( sharedAva.equals( referenceAva ) );
        assertTrue( referenceAva.equals( sharedAva ) );

        assertTrue( referenceRdn.equals( sharedRdn ) );
        assertTrue( sharedRdn.equals( referenceRdn ) );

        assertEquals( referenceDn, sharedDn );
        assertEquals( sharedDn, referenceDn );
    }
}
