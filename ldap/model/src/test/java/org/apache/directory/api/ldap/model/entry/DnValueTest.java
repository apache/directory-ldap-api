/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.entry;


import static org.junit.Assert.assertEquals;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.comparators.DnComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DnNormalizer;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DnSyntaxChecker;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the Value class with Dn values
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DnValueTest
{
    private static EntryUtils.S s;
    private static EntryUtils.AT at;
    private static EntryUtils.MR mr;


    /**
     * Initialize an AttributeType and the associated MatchingRule 
     * and Syntax
     */
    @BeforeClass
    public static void initAT()
    {
        s = new EntryUtils.S( "1.1.1.1", true );
        s.setSyntaxChecker( DnSyntaxChecker.INSTANCE );
        mr = new EntryUtils.MR( "1.1.2.1" );
        mr.setSyntax( s );
        mr.setLdapComparator( new DnComparator( "1.1.2.1" ) );
        mr.setNormalizer( new DnNormalizer() );
        at = new EntryUtils.AT( "1.1.3.1" );
        at.setEquality( mr );
        at.setOrdering( mr );
        at.setSubstring( mr );
        at.setSyntax( s );
    }


    @Test
    public void testEqualsSimpleDn() throws LdapException
    {
        Value sv1 = new Value( at, "cn=user2,ou=system" );
        Value sv2 = new Value( at, " cn = user2 , ou = system " );
        assertEquals( sv1, sv2 );
    }


    @Test
    public void testEqualsComplexDn() throws LdapException
    {
        Value sv1 = new Value( at, "cn=\\#\\\\\\+\\, \\\"\u00F6\u00E9\\\",ou=system" );
        Value sv2 = new Value( at, " cn = \\#\\\\\\+\\, \\\"\u00F6\u00E9\\\" , ou = system " );
        assertEquals( sv1, sv2 );
    }
}
