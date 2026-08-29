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
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test that Rdn.hashCode() actually computes a hash: it previously always
 * returned 0 due to a shadowed local variable, collapsing every Dn/Rdn-keyed
 * hash collection into a single bucket (quadratic lookups, a DoS vector for
 * attacker-influenced DN sets).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class RdnHashCodeTest
{
    @Test
    public void testRdnHashCodeIsNotZero() throws LdapException
    {
        assertNotEquals( 0, new Rdn( "cn=test" ).hashCode() );
    }


    @Test
    public void testEqualRdnsHaveEqualHashCodes() throws LdapException
    {
        assertEquals( new Rdn( "cn=test" ).hashCode(), new Rdn( "cn=test" ).hashCode() );
        assertNotEquals( 0, new Rdn( "a=b + c=d" ).hashCode() );
        assertNotEquals( 0, new Rdn( "c=d + a=b" ).hashCode() );
        assertEquals( new Rdn( "a=b + c=d" ).hashCode(), new Rdn( "c=d + a=b" ).hashCode() );
    }


    @Test
    public void testDifferentRdnsHaveDifferentHashCodes() throws LdapException
    {
        assertNotEquals( new Rdn( "cn=test" ).hashCode(), new Rdn( "cn=other" ).hashCode() );
    }


    @Test
    public void testDnsWithSameRdnCountDoNotAllCollide() throws LdapException
    {
        // Previously any two Dns with the same number of RDNs had the same hashCode
        assertNotEquals( new Dn( "cn=a,dc=x" ).hashCode(), new Dn( "cn=b,dc=y" ).hashCode() );
    }
}
