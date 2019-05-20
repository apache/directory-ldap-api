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
package org.apache.directory.api.ldap.model.schema.syntaxes;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.schema.syntaxCheckers.NisNetgroupTripleSyntaxChecker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test cases for NisNetgroupTripleSyntaxChecker.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class NisNetgroupTripleSyntaxCheckerTest
{
    NisNetgroupTripleSyntaxChecker checker = NisNetgroupTripleSyntaxChecker.INSTANCE;


    @Test
    public void testNullString()
    {
        assertFalse( checker.isValidSyntax( null ) );
    }


    @Test
    public void testEmptyString()
    {
        assertFalse( checker.isValidSyntax( "" ) );
    }


    @Test
    public void testWrongCase()
    {
        assertFalse( checker.isValidSyntax( "(,," ) );
        assertFalse( checker.isValidSyntax( ",,)" ) );
        assertFalse( checker.isValidSyntax( "( , , )" ) );
        assertFalse( checker.isValidSyntax( "(A,B,1)" ) );
        assertFalse( checker.isValidSyntax( "(A_=v,b,D)" ) );
        assertFalse( checker.isValidSyntax( "(a, ,c)" ) );
    }


    @Test
    public void testCorrectCase()
    {
        assertTrue( checker.isValidSyntax( "(,,)" ) );
        assertTrue( checker.isValidSyntax( "(a,,b)" ) );
        assertTrue( checker.isValidSyntax( "(test,test,test)" ) );
    }
}
