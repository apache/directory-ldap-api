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


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;

import org.apache.directory.api.ldap.model.schema.syntaxCheckers.FacsimileTelephoneNumberSyntaxChecker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test cases for FacsimileTelephoneNumberSyntaxChecker.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class FacsimileTelephoneNumberSyntaxCheckerTest
{
    FacsimileTelephoneNumberSyntaxChecker checker = FacsimileTelephoneNumberSyntaxChecker.INSTANCE;


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
    public void testCorrectTelephoneNumber()
    {
        assertTrue( checker.isValidSyntax( "1" ) );
        assertTrue( checker.isValidSyntax( "1111" ) );
        assertTrue( checker.isValidSyntax( "1 (2) 3" ) );
        assertTrue( checker.isValidSyntax( "+ 123 ( 456 )7891   12345" ) );
        assertTrue( checker.isValidSyntax( " 12 34 56 78 90 " ) );
    }


    @Test
    public void testWithNewMandatoryRegexp()
    {
        // Adding french telephone number regexp
        checker = FacsimileTelephoneNumberSyntaxChecker.builder().
            setDefaultRegexp( " *0[1-8](( *|[-/.]{1})\\d\\d){4} *" ).build();

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
        checker = FacsimileTelephoneNumberSyntaxChecker.builder().build();
        assertTrue( checker.isValidSyntax( "1" ) );
    }


    @Test
    public void testCorrectTelephoneNumberAndFaxParam()
    {
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensional" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$fineResolution" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$unlimitedLength" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$b4Length" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$a3Width" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$b4Width" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensional" ) );
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$uncompressed" ) );
    }


    @Test
    public void testCorrectTelephoneNumberAndFaxParams()
    {
        assertTrue( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensional$fineResolution$a3Width" ) );
    }


    @Test
    public void testCorrectTelephoneNumberBadFaxParams()
    {
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$$" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensionnal" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$ twoDimensional" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensional$" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$twoDimensional$twoDimensional" ) );
        assertFalse( checker.isValidSyntax( "+ 33 1 (456) 7891   12345$b4Width$ $a3Width" ) );
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

        assertTimeoutPreemptively( Duration.ofSeconds( 5 ),
            () -> assertFalse( checker.isValidSyntax( attack + "$twoDimensional" ) ) );

        // An invalid telephone number part must be rejected whatever the logging
        // level (the rejection used to be guarded by LOG.isDebugEnabled()), and
        // the character right before the '$' is part of the number
        assertFalse( checker.isValidSyntax( "12A$twoDimensional" ) );

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
