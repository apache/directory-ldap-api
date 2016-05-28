/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.schema;

import java.io.IOException;

import org.apache.directory.api.util.exception.InvalidCharacterException;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/**
 * Tests for the PrepareString class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PrepareStringTest
{
    @Test
    public void testEscapeBackSlash() throws IOException
    {
        String result = PrepareString.normalize( "C:\\a\\b\\c" );
        System.out.println( result );
    }
    
    //-------------------------------------------------------------------------
    // Test the PrepareString.insignificantSpacesStringInitial method
    //-------------------------------------------------------------------------
    @Test 
    public void insignificantSpacesStringInitialNull() throws InvalidCharacterException
    {
        char[] empty = null;
        assertEquals( " ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialEmpty() throws InvalidCharacterException
    {
        char[] empty = new char[]{};
        assertEquals( " ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ' };
        assertEquals( " ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', ' '};
        assertEquals( " ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c' };
        assertEquals( " abc", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialOneSpaceA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialNSpacesA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialOneSpaceABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a', 'b', 'c' };
        assertEquals( " abc", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialNSpacesABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a', 'b', 'c' };
        assertEquals( " abc", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialInnerOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', 'b', ' ', 'c' };
        assertEquals( " a  b  c", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialInnerNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c' };
        assertEquals( " a  b  c", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialEndingOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ' };
        assertEquals( " a ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialEndingNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', ' ' };
        assertEquals( " a ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringInitialAll() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c', ' ', ' ', ' ' };
        assertEquals( " a  b  c ", PrepareString.insignificantSpacesStringInitial( empty ) );
    }
    
    
    //-------------------------------------------------------------------------
    // Test the PrepareString.insignificantSpacesStringFinal method
    //-------------------------------------------------------------------------
    @Test 
    public void insignificantSpacesStringFinalNull() throws InvalidCharacterException
    {
        char[] empty = null;
        assertEquals( " ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalEmpty() throws InvalidCharacterException
    {
        char[] empty = new char[]{};
        assertEquals( " ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ' };
        assertEquals( " ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', ' '};
        assertEquals( " ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c' };
        assertEquals( "abc ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalAOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalANSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalABCOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c', ' ' };
        assertEquals( "abc ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalABCNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c', ' ', ' ', ' ' };
        assertEquals( "abc ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalInnerOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', 'b', ' ', 'c' };
        assertEquals( "a  b  c ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalInnerNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c' };
        assertEquals( "a  b  c ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalStartingOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a' };
        assertEquals( " a ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalStartingNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a'};
        assertEquals( " a ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringFinalAll() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c', ' ', 'd' };
        assertEquals( " a  b  c  d ", PrepareString.insignificantSpacesStringFinal( empty ) );
    }
    
    
    //-------------------------------------------------------------------------
    // Test the PrepareString.insignificantSpacesStringAny method
    //-------------------------------------------------------------------------
    @Test 
    public void insignificantSpacesStringAnyNull() throws InvalidCharacterException
    {
        char[] empty = null;
        assertEquals( " ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyEmpty() throws InvalidCharacterException
    {
        char[] empty = new char[]{};
        assertEquals( " ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ' };
        assertEquals( " ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', ' '};
        assertEquals( " ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a' };
        assertEquals( "a", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c' };
        assertEquals( "abc", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyAOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyANSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyOneSpaceA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyNSpacesA() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyABCOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c', ' ' };
        assertEquals( "abc ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyABCNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', 'b', 'c', ' ', ' ', ' ' };
        assertEquals( "abc ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyOneSpaceABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a', 'b', 'c' };
        assertEquals( " abc", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyNSpacesABC() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a', 'b', 'c' };
        assertEquals( " abc", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyInnerOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', 'b', ' ', 'c' };
        assertEquals( "a  b  c", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyInnerNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c' };
        assertEquals( "a  b  c", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyStartingOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a' };
        assertEquals( " a", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyStartingNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a'};
        assertEquals( " a", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyEndingOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyEndingNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ 'a', ' ', ' ', ' ' };
        assertEquals( "a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyStartingEndingOneSpace() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', 'a', ' ' };
        assertEquals( " a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyStartingEndingNSpaces() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a', ' ', ' ', ' ' };
        assertEquals( " a ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
    
    
    @Test 
    public void insignificantSpacesStringAnyAll() throws InvalidCharacterException
    {
        char[] empty = new char[]{ ' ', ' ', ' ', 'a', ' ', ' ', 'b', ' ', ' ', ' ', ' ', 'c', ' ', 'd', ' ', ' ', ' ' };
        assertEquals( " a  b  c  d ", PrepareString.insignificantSpacesStringAny( empty ) );
    }
}
