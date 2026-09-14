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

package org.apache.directory.api.ldap.model.subtree;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.text.ParseException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the Subtree Specification parser bounds the nesting depth of the
 * refinement grammar ('and', 'or', 'not') instead of dying with a
 * StackOverflowError on deeply nested hostile input.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SubtreeSpecificationParserDepthTest
{
    /**
     * Build a specificationFilter with the given number of nested 'not:' refinements.
     */
    private String deeplyNestedSpec( int depth )
    {
        StringBuilder sb = new StringBuilder( "{ specificationFilter and:{ " );

        for ( int i = 0; i < depth; i++ )
        {
            sb.append( "not: " );
        }

        sb.append( "item:2.5.6.2 } }" );

        return sb.toString();
    }


    /**
     * A reasonably nested refinement must still be accepted.
     */
    @Test
    public void testShallowRefinementStillParses() throws Exception
    {
        SubtreeSpecificationParser parser = new SubtreeSpecificationParser( null );

        assertTrue( parser.check( deeplyNestedSpec( 10 ) ) );
    }


    /**
     * A refinement nested beyond the maximum depth must be rejected with a
     * ParseException, not a StackOverflowError.
     */
    @Test
    public void testTooDeepRefinementIsRejected() throws Exception
    {
        SubtreeSpecificationParser parser = new SubtreeSpecificationParser( null );

        assertThrows( ParseException.class, () -> parser.parse( deeplyNestedSpec( 200 ) ) );
    }


    /**
     * A hostile, massively nested refinement must be rejected cleanly. Before the
     * depth limit was added, this input killed the calling thread with a
     * StackOverflowError (which check() does not catch).
     */
    @Test
    public void testHostileNestingDoesNotOverflowTheStack() throws Exception
    {
        SubtreeSpecificationParser parser = new SubtreeSpecificationParser( null );

        assertFalse( parser.check( deeplyNestedSpec( 20000 ) ) );
    }
}
