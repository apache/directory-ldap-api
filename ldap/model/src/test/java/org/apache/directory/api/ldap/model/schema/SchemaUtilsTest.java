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
package org.apache.directory.api.ldap.model.schema;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * The unit tests for methods on SchemaUtils.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class SchemaUtilsTest
{
    public static LdapSyntax[] getSyntaxes()
    {
        LdapSyntax[] syntaxes = new LdapSyntax[3];
        syntaxes[0] = new LdapSyntax( "1.3.6.1.4.1.1466.115.121.1.12", "Dn syntax", true );
        syntaxes[1] = new LdapSyntax( "1.3.6.1.4.1.1466.115.121.1.15", "Directory String syntax", true );
        syntaxes[2] = new LdapSyntax( "1.3.6.1.4.1.1466.115.121.1.58", "Substring assertion syntax", true );

        return syntaxes;
    }


    public static MatchingRule[] getMatchingRules()
    {
        MatchingRule[] mrs = new MatchingRule[3];

        mrs[0] = new MatchingRule( "2.5.13.2" );
        mrs[0].setSyntax( getSyntaxes()[1] );
        mrs[0].addName( "caseIgnoreMatch" );
        mrs[0].setDescription( "Ignores case in strings" );

        mrs[1] = new MatchingRule( "2.5.13.4" );
        mrs[0].setSyntax( getSyntaxes()[2] );
        mrs[1].addName( "caseIgnoreSubstringsMatch" );
        mrs[1].setDescription( "Ignores case in substrings" );

        mrs[2] = new MatchingRule( "2.5.13.1" );
        mrs[0].setSyntax( getSyntaxes()[0] );
        mrs[2].addName( "distinguishedNameMatch" );
        mrs[2].setDescription( "distinguishedNameMatch" );

        return mrs;
    }


    public AttributeType[] getAttributeTypes()
    {
        AttributeType[] ats = new AttributeType[5];

        ats[0] = new AttributeType( "2.5.4.41" );
        ats[0].addName( "name" );
        ats[0].setSyntax( getSyntaxes()[1] );
        ats[0].setSyntaxLength( 32768 );
        ats[0].setEquality( getMatchingRules()[0] );
        ats[0].setSubstring( getMatchingRules()[1] );

        // ( 2.5.4.3 NAME 'cn' SUP name )
        ats[1] = new AttributeType( "2.5.4.3" );
        ats[1].addName( "cn", "commonName" );

        ats[2] = new AttributeType( "2.5.4.41" );
        ats[2].addName( "name" );
        ats[2].setSyntax( getSyntaxes()[1] );
        ats[2].setSyntaxLength( 32768 );
        ats[2].setEquality( getMatchingRules()[0] );
        ats[2].setSubstring( getMatchingRules()[1] );

        ats[3] = new AttributeType( "2.5.4.41" );
        ats[3].addName( "name" );
        ats[3].setSyntax( getSyntaxes()[1] );
        ats[3].setSyntaxLength( 32768 );
        ats[3].setEquality( getMatchingRules()[0] );
        ats[3].setSubstring( getMatchingRules()[1] );

        ats[4] = new AttributeType( "2.5.4.41" );
        ats[4].addName( "name" );
        ats[4].setSyntax( getSyntaxes()[1] );
        ats[4].setSyntaxLength( 32768 );
        ats[4].setEquality( getMatchingRules()[0] );
        ats[4].setSubstring( getMatchingRules()[1] );

        return ats;
    }


    /**
     * Tests rendering operations on qdescrs render method. Both overloaded
     * operations {@link org.apache.directory.api.ldap.model.schema.SchemaUtils#renderQDescrs(StringBuilder, List)} 
     */
    @Test
    public void testRenderQdescrs()
    {
        assertEquals( "", SchemaUtils.renderQDescrs( new StringBuilder(), ( List<String> ) null ).toString() );
        assertEquals( "", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            {} ) ).toString() );
        assertEquals( "'name1'", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            { "name1" } ) ).toString() );
        assertEquals( "( 'name1' 'name2' )", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            { "name1", "name2" } ) ).toString() );
        assertEquals( "( 'name1' 'name2' 'name3' )",
            SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
                { "name1", "name2", "name3" } ) ).toString() );

        assertEquals( "", SchemaUtils.renderQDescrs( new StringBuilder(), ( List<String> ) null ).toString() );

        assertEquals( "", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            {} ) ).toString() );

        assertEquals( "'name1'", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            { "name1" } ) ).toString() );

        assertEquals( "( 'name1' 'name2' )", SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
            { "name1", "name2" } ) ).toString() );

        assertEquals( "( 'name1' 'name2' 'name3' )",
            SchemaUtils.renderQDescrs( new StringBuilder(), Arrays.asList( new String[]
                { "name1", "name2", "name3" } ) ).toString() );
    }
    
    
    /**
     * Test the isAttributeNameValid method
     */
    @Test
    public void testIsAttributeNameValid()
    {
        assertFalse( SchemaUtils.isAttributeNameValid( null ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "    " ) );
        
        // Descr
        assertTrue( SchemaUtils.isAttributeNameValid( "a" ) );
        assertTrue( SchemaUtils.isAttributeNameValid( "ObjectClass-text_test123" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "-text_test123" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "text_te&st123" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "text_te st123" ) );
        
        // Numericoid
        assertTrue( SchemaUtils.isAttributeNameValid( "0" ) );
        assertTrue( SchemaUtils.isAttributeNameValid( "0" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "00.1.2.3" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "0.1.2..3" ) );
        assertFalse( SchemaUtils.isAttributeNameValid( "0.01.2.3" ) );
    }
}
