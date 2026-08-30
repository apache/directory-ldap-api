/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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


import static org.apache.directory.ldap.client.api.search.FilterBuilder.contains;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.extensible;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.present;
import static org.apache.directory.ldap.client.api.search.FilterBuilder.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;


/**
 * Tests that no operand of the FilterBuilder API can alter the structure of
 * the produced filter : the attribute description and matching rule operands
 * are concatenated unescaped, so they must be validated against the RFC 4512
 * attributedescription grammar. Otherwise an attacker-controlled 'attribute
 * name' like "uid=admin)(roomNumber" would inject arbitrary clauses through
 * the library's own safe-construction API.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterOperandValidationTest
{
    @Test
    public void testEqualRejectsFilterInjectionInAttribute()
    {
        assertThrows( IllegalArgumentException.class,
            () -> equal( "uid=admin)(roomNumber", "1234" ) );
        assertThrows( IllegalArgumentException.class,
            () -> equal( "cn=*)(uid=admin", "x" ) );
        assertThrows( IllegalArgumentException.class,
            () -> equal( "", "x" ) );
        assertThrows( IllegalArgumentException.class,
            () -> equal( null, "x" ) );
    }


    @Test
    public void testPresentRejectsFilterInjectionInAttribute()
    {
        assertThrows( IllegalArgumentException.class,
            () -> present( "cn=x)(uid=admin" ) );
    }


    @Test
    public void testSubstringRejectsFilterInjectionInAttribute()
    {
        assertThrows( IllegalArgumentException.class,
            () -> startsWith( "cn=x)(uid=admin", "adm" ) );
        assertThrows( IllegalArgumentException.class,
            () -> contains( "cn=x)(uid=admin", "adm" ) );
    }


    @Test
    public void testExtensibleRejectsFilterInjectionInAttribute()
    {
        assertThrows( IllegalArgumentException.class,
            () -> extensible( "cn:dn:=x)(uid=admin", "x" ) );
    }


    @Test
    public void testSetMatchingRuleRejectsFilterInjection()
    {
        assertThrows( IllegalArgumentException.class,
            () -> extensible( "cn", "x" ).setMatchingRule( "caseExactMatch:=x)(cn=*" ) );
        assertThrows( IllegalArgumentException.class,
            () -> extensible( "cn", "x" ).setMatchingRule( "dn:caseExactMatch" ) );
    }


    @Test
    public void testValidOperandsStillAccepted()
    {
        // keystring attribute
        assertEquals( "(cn=x)", equal( "cn", "x" ).toString() );
        
        // Keystring with spacek
        assertEquals( "(cn =x)", equal( "cn ", "x" ).toString() );

        // numeric OID attribute
        assertEquals( "(2.5.4.3=x)", equal( "2.5.4.3", "x" ).toString() );

        // attribute description with options
        assertEquals( "(userCertificate;binary=*)", present( "userCertificate;binary" ).toString() );
        assertEquals( "(cn;lang-en=x)", equal( "cn;lang-en", "x" ).toString() );

        // matching rule as a name and as an OID
        assertEquals( "(cn:caseExactMatch:=x)",
            extensible( "cn", "x" ).setMatchingRule( "caseExactMatch" ).toString() );
        assertEquals( "(cn:2.5.13.5:=x)",
            extensible( "cn", "x" ).setMatchingRule( "2.5.13.5" ).toString() );
    }
}
