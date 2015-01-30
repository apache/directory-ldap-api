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
package org.apache.directory.ldap.client.api.search;


import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.contains;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.endsWith;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.extensible;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.not;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.or;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.startsWith;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.substring;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;


/**
 * Unit tests for {@link FilterBuilder}.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterBuilderTest
{
    @Test
    public void testExtensible()
    {
        assertEquals( "(cn:caseExactMatch:=Fred Flintstone)", 
            extensible( "cn", "Fred Flintstone" )
                .setMatchingRule( "caseExactMatch" ).toString() );
    }

    @Test
    public void testFilterBuilder()
    {
        assertEquals( "(cn=Babs Jensen)", equal( "cn", "Babs Jensen" ).toString() );
        assertEquals( "(!(cn=Tim Howes))", not( equal( "cn", "Tim Howes" ) ).toString() );
        assertEquals( "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J\\2A)))",
            and( equal( "objectClass", "Person" ),
                or( equal( "sn", "Jensen" ),
                    equal( "cn", "Babs J*" ) ) ).toString() );
        assertEquals( "(o=univ\\2Aof\\2Amich\\2A)", equal( "o", "univ*of*mich*" ).toString() );
    }


    /**
     * Test the substring builder startsWith method
     */
    @Test
    public void testSubstringFilterBuilderStartsWith()
    {
        try
        {
            assertEquals( "(o=*)", startsWith( "o" ).toString() );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            // Expected
        }
        assertEquals( "(o=univ*)", startsWith( "o", "univ" ).toString() );
        assertEquals( "(o=univ*of*mich*)", startsWith( "o", "univ", "of", "mich" ).toString() );
    }


    /**
     * Test the substring builder endsWith method
     */
    @Test
    public void testSubstringFilterBuilderEndsWith()
    {
        try
        {
            assertEquals( "(o=*)", endsWith( "o" ).toString() );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            // Expected
        }
        assertEquals( "(o=*igan)", endsWith( "o", "igan" ).toString() );
        assertEquals( "(o=*sit*of*igan)", endsWith( "o", "sit", "of", "igan" ).toString() );
    }


    /**
     * Test the substring builder contains method
     */
    @Test
    public void testSubstringFilterBuilderContains()
    {
        try
        {
            assertEquals( "(o=*)", contains( "o" ).toString() );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            // Expected
        }
        assertEquals( "(o=*of*)", contains( "o", "of" ).toString() );
        assertEquals( "(o=*sit*of*chi*)", contains( "o", "sit", "of", "chi" ).toString() );
        assertEquals( "(cn=*\u00e9*)", contains( "cn", "\u00e9" ).toString() );
        assertEquals( "(cn=*\\C3\\E9*)", contains( "cn", "\\C3\\E9" ).toString() );
    }


    /**
     * Test the substring builder substring method
     */
    @Test
    public void testSubstringFilterBuilderSubstring()
    {
        try
        {
            assertEquals( "(o=*)", substring( "o" ).toString() );
            fail();
        }
        catch ( IllegalArgumentException iae )
        {
            // Expected
        }
        assertEquals( "(o=of*)", substring( "o", "of" ).toString() );
        assertEquals( "(o=the*igan)", substring( "o", "the", "igan" ).toString() );
        assertEquals( "(o=the*sit*of*igan)", substring( "o", "the", "sit", "of", "igan" ).toString() );
    }
}
