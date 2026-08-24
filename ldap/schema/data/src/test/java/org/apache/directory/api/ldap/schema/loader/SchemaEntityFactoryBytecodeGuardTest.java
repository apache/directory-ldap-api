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


import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.parsers.SyntaxCheckerDescription;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that SchemaEntityFactory does not execute code carried by schema
 * entries : loading classes from the m-bytecode attribute must be refused
 * unless explicitly enabled, and an FQCN-only description must not lead to
 * the instantiation of a class which is not of the expected schema element
 * type.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.SAME_THREAD)
public class SchemaEntityFactoryBytecodeGuardTest
{
    /**
     * Loading a schema element from entry-provided bytecode must be refused
     * by default, before the bytecode is even handed to a ClassLoader.
     */
    @Test
    public void testBytecodeLoadingIsRefusedByDefault() throws Exception
    {
        SchemaManager schemaManager = new DefaultSchemaManager();
        SchemaEntityFactory factory = new SchemaEntityFactory();

        SyntaxCheckerDescription description = new SyntaxCheckerDescription( "1.3.6.1.4.1.99999.1" );
        description.setFqcn( "evil.Gadget" );
        // Some (junk) base64 bytecode : it must be refused before being looked at
        description.setBytecode( "yv66vgAAADQ=" );

        try
        {
            factory.getSyntaxChecker( schemaManager, description, schemaManager.getRegistries(), "system" );
            fail( "Loading a schema element from entry-provided bytecode should be refused by default" );
        }
        catch ( LdapException le )
        {
            assertTrue( le.getMessage().contains( SchemaEntityFactory.BYTECODE_LOADING_PROPERTY ) );
        }
    }


    /**
     * An FQCN-only entry naming a class which is not a SyntaxChecker must be
     * rejected before the class is instantiated.
     */
    @Test
    public void testFqcnMustBeOfTheExpectedType() throws Exception
    {
        SchemaManager schemaManager = new DefaultSchemaManager();
        SchemaEntityFactory factory = new SchemaEntityFactory();

        Entry entry = new DefaultEntry();
        entry.setDn( new Dn( "m-oid=1.3.6.1.4.1.99999.2,ou=syntaxCheckers,cn=system,ou=schema" ) );
        entry.add( "m-oid", "1.3.6.1.4.1.99999.2" );
        // A class present on the classpath which is NOT a SyntaxChecker
        entry.add( "m-fqcn", "java.util.ArrayList" );

        assertThrows( LdapException.class,
            () -> factory.getSyntaxChecker( schemaManager, entry, schemaManager.getRegistries(), "system" ) );
    }
}