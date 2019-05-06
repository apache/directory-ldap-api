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
package org.apache.directory.api.ldap.model.message;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * TestCase for the ExtendedResponse class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class OpaqueExtendedResponseTest
{
    /**
     * Creates and populates a ExtendedResponseImpl stub for testing purposes.
     * 
     * @return a populated ExtendedResponseImpl stub
     */
    private ExtendedResponse createStub()
    {
        // Construct the Search response to test with results and referrals
        ExtendedResponse response = new OpaqueExtendedResponse( 45 );
        response.setResponseName( "1.1.1.1" );
        LdapResult result = response.getLdapResult();

        try
        {
            result.setMatchedDn( new Dn( "dc=example,dc=com" ) );
        }
        catch ( LdapException ine )
        {
            // Do nothing
        }

        result.setResultCode( ResultCodeEnum.SUCCESS );
        ReferralImpl refs = new ReferralImpl();
        refs.addLdapUrl( "ldap://someserver.com" );
        refs.addLdapUrl( "ldap://apache.org" );
        refs.addLdapUrl( "ldap://another.net" );
        result.setReferral( refs );
        return response;
    }


    /**
     * Tests for equality using the same object.
     */
    @Test
    public void testEqualsSameObj()
    {
        ExtendedResponse resp = createStub();
        assertTrue( resp.equals( resp ) );
    }


    /**
     * Tests for equality using an exact copy.
     */
    @Test
    public void testEqualsExactCopy()
    {
        ExtendedResponse resp0 = createStub();
        ExtendedResponse resp1 = createStub();
        assertTrue( resp0.equals( resp1 ) );
        assertTrue( resp1.equals( resp0 ) );
    }


    /**
     * Tests for equality using different stub implementations.
     * @throws LdapInvalidDnException 
     */
    @Test
    public void testEqualsDiffImpl() throws LdapInvalidDnException
    {
        ExtendedResponse resp0 = createStub();
        ExtendedResponse resp1 = new OpaqueExtendedResponse( 45, "1.1.1.1" );
        resp1.getLdapResult().setMatchedDn( new Dn( "dc=example,dc=com" ) );
        resp1.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
        ReferralImpl refs = new ReferralImpl();
        refs.addLdapUrl( "ldap://someserver.com" );
        refs.addLdapUrl( "ldap://apache.org" );
        refs.addLdapUrl( "ldap://another.net" );
        resp1.getLdapResult().setReferral( refs );

        assertTrue( resp0.equals( resp1 ) );
        assertTrue( resp1.equals( resp0 ) );
    }


    /**
     * Tests for equal hashCode using the same object.
     */
    @Test
    public void testHashCodeSameObj()
    {
        ExtendedResponse resp = createStub();
        assertTrue( resp.hashCode() == resp.hashCode() );
    }


    /**
     * Tests for equal hashCode using an exact copy.
     */
    @Test
    public void testHashCodeExactCopy()
    {
        ExtendedResponse resp0 = createStub();
        ExtendedResponse resp1 = createStub();
        assertTrue( resp0.hashCode() == resp1.hashCode() );
    }


    /**
     * Tests inequality when messageIds are different.
     */
    @Test
    public void testNotEqualsDiffIds()
    {
        ExtendedResponse resp0 = new OpaqueExtendedResponse( 3 );
        ExtendedResponse resp1 = new OpaqueExtendedResponse( 4 );

        assertFalse( resp0.equals( resp1 ) );
        assertFalse( resp1.equals( resp0 ) );
    }


    /**
     * Tests inequality when responseNames are different.
     */
    @Test
    public void testNotEqualsDiffNames()
    {
        ExtendedResponse resp0 = createStub();
        resp0.setResponseName( "1.2.3.4" );
        ExtendedResponse resp1 = createStub();
        resp1.setResponseName( "1.2.3.4.5" );

        assertFalse( resp0.equals( resp1 ) );
        assertFalse( resp1.equals( resp0 ) );
    }
}
