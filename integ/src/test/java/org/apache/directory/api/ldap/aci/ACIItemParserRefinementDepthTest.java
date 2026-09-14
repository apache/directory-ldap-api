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

package org.apache.directory.api.ldap.aci;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;

import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.loader.JarLdifSchemaLoader;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the ACIItem refinement parser bounds its recursion depth: a
 * deeply nested 'classes' refinement (e.g. 'not: not: not: ...') must fail
 * with a ParseException instead of a StackOverflowError, both through
 * parse() and through check() (the path used by ACIItemSyntaxChecker for
 * every stored value of the ACI syntax).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class ACIItemParserRefinementDepthTest
{
    /** the ACIItem parser wrapper */
    private static ACIItemParser parser;


    /**
     * Initialization
     *
     * @throws Exception If the setup failed
     */
    @BeforeAll
    public static void init() throws Exception
    {
        JarLdifSchemaLoader loader = new JarLdifSchemaLoader();
        SchemaManager schemaManager = new DefaultSchemaManager( loader );
        schemaManager.loadAllEnabled();

        parser = new ACIItemParser( schemaManager );
    }


    private String itemWithRefinement( String refinement )
    {
        return "{  "
            + "  identificationTag  \"id1\" , "
            + "  precedence 14  , "
            + "  authenticationLevel none  , "
            + "  itemOrUserFirst itemFirst  : "
            + "  { "
            + "    protectedItems  "
            + "    { "
            + "      classes " + refinement + " "
            + "    }  , "
            + "    itemPermissions "
            + "    { "
            + "      { "
            + "        userClasses "
            + "        { "
            + "          allUsers "
            + "        }  , "
            + "        grantsAndDenials "
            + "        { "
            + "          grantBrowse "
            + "        } "
            + "      } "
            + "    } "
            + "  } "
            + "}";
    }


    private String nestedNotRefinement( int depth )
    {
        StringBuilder refinement = new StringBuilder();

        for ( int i = 0; i < depth; i++ )
        {
            refinement.append( "not: " );
        }

        refinement.append( "item: 2.5.6.6" );

        return itemWithRefinement( refinement.toString() );
    }


    /**
     * A moderately nested refinement must still parse.
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testModeratelyNestedRefinementStillParses() throws Exception
    {
        ACIItem item = parser.parse( nestedNotRefinement( 10 ) );
        assertNotNull( item );
        assertTrue( parser.check( nestedNotRefinement( 10 ) ) );
    }


    /**
     * A refinement nested past the limit must fail with a ParseException,
     * not a StackOverflowError.
     */
    @Test
    public void testDeeplyNestedRefinementRejected()
    {
        String spec = nestedNotRefinement( 20000 );

        assertThrows( ParseException.class, () -> parser.parse( spec ) );

        // check() is the ACIItemSyntaxChecker path: it must return false,
        // not let an Error escape the validating thread
        assertFalse( parser.check( spec ) );
    }
}
