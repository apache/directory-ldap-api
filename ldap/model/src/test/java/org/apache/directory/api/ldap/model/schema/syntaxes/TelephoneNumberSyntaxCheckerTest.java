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
package org.apache.directory.api.ldap.model.schema.syntaxes;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;

import org.apache.directory.api.ldap.model.schema.syntaxCheckers.TelephoneNumberSyntaxChecker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test cases for NumericStringSyntaxChecker.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class TelephoneNumberSyntaxCheckerTest
{
    TelephoneNumberSyntaxChecker checker = TelephoneNumberSyntaxChecker.INSTANCE;


    @Test
    public void testNullString()
    {
        assertFalse( checker.isValidSyntax( null ) );
    }


    @Test
    public void testOID()
    {
        assertEquals( "1.3.6.1.4.1.1466.115.121.1.50", checker.getOid() );
    }


    @Test
    public void testEmptyString()
    {
        assertFalse( checker.isValidSyntax( "" ) );
    }


    @Test
    public void testOneCharString()
    {
        assertFalse( checker.isValidSyntax( "A" ) );
        assertFalse( checker.isValidSyntax( "+" ) );
    }


    @Test
    public void testWrongCase()
    {
        assertFalse( checker.isValidSyntax( "123 456 f" ) );
        assertFalse( checker.isValidSyntax( "+ ()" ) );
        assertFalse( checker.isValidSyntax( " +2 (123) 456-789 +" ) );
    }


    @Test
    public void testCorrectCase()
    {
        assertTrue( checker.isValidSyntax( "1" ) );
        assertTrue( checker.isValidSyntax( "1111" ) );
        assertTrue( checker.isValidSyntax( "1 (2) 3" ) );
        assertTrue( checker.isValidSyntax( "+ 123 ( 456 )7891   12345" ) );
        assertTrue( checker.isValidSyntax( " 12 34 56 78 90 " ) );
        assertTrue( checker.isValidSyntax( " + 12 34 ; 56* 78 90, # " ) );
    }


    @Test
    public void testWithNewMandatoryRegexp()
    {
        // Adding french telephone number regexp
        checker = TelephoneNumberSyntaxChecker.builder().setDefaultRegexp( " *0[1-8](( *|[-/.]{1})\\d\\d){4} *" ).build();

        assertFalse( checker.isValidSyntax( "+ 123 ( 456 )7891   12345" ) );
        assertTrue( checker.isValidSyntax( " 01 02 03 04 05 " ) );
        assertTrue( checker.isValidSyntax( " 0102 03 04 05 " ) );
        assertTrue( checker.isValidSyntax( " 01 02 03 04  05 " ) );
        assertTrue( checker.isValidSyntax( " 01/02/03/04/05 " ) );
        assertFalse( checker.isValidSyntax( " 01 / 02 .03 04--  05 " ) );
    }


    @Test
    public void testBuilderSetsDefaultPattern()
    {
        checker = TelephoneNumberSyntaxChecker.builder().build();
        assertTrue( checker.isValidSyntax( "1" ) );
    }


    @Test
    public void testNoCatastrophicBacktracking()
    {
        // A long digit run followed by one non matching character used to send
        // the previous default regexp into exponential backtracking (ReDoS) :
        // the match must stay linear in the value length
        StringBuilder sb = new StringBuilder();

        for ( int i = 0; i < 200; i++ )
        {
            sb.append( '1' );
        }

        sb.append( 'A' );

        String attack = sb.toString();

        assertTimeoutPreemptively( Duration.ofSeconds( 5 ),
            () -> assertFalse( checker.isValidSyntax( attack ) ) );

        // And the equivalent valid value still matches
        assertTimeoutPreemptively( Duration.ofSeconds( 5 ),
            () -> assertTrue( checker.isValidSyntax( attack.substring( 0, attack.length() - 1 ) ) ) );

        // Values above the length cap are rejected up front, bounding both the
        // matching work and the regexp engine's recursion depth
        StringBuilder big = new StringBuilder();

        for ( int i = 0; i < 100000; i++ )
        {
            big.append( '1' );
        }

        String bigValue = big.toString();

        assertTimeoutPreemptively( Duration.ofSeconds( 5 ),
            () -> assertFalse( checker.isValidSyntax( bigValue ) ) );
    }
}
