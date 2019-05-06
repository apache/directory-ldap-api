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

import java.util.Collection;
import java.util.Collections;

import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ReferralImpl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the ReferralImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 *         $Rev: 946251 $
 */
@Execution(ExecutionMode.CONCURRENT)
public class ReferralImplTest
{
    /**
     * Tests to make sure the equals method works for the same exact object.
     */
    @Test
    public void testEqualsSameObject()
    {
        ReferralImpl refs = new ReferralImpl();
        assertTrue( refs.equals( refs ), "equals method should work for the same object" );
    }


    /**
     * Tests to make sure the equals method works for two objects that are the
     * same exact copy of one another.
     */
    @Test
    public void testEqualsExactCopy()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        refs1.addLdapUrl( "ldap://blah2" );
        assertTrue( refs0.equals( refs1 ), "exact copies of Referrals should be equal" );
        assertTrue( refs1.equals( refs0 ), "exact copies of Referrals should be equal" );
    }


    /**
     * Tests to make sure the equals method works for two objects that are the
     * same exact copy of one another but there are redundant entries.
     */
    @Test
    public void testEqualsExactCopyWithRedundancy()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        refs0.addLdapUrl( "ldap://blah2" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        refs1.addLdapUrl( "ldap://blah2" );
        refs1.addLdapUrl( "ldap://blah2" );
        assertTrue( refs0.equals( refs1 ), "exact copies of Referrals should be equal" );
        assertTrue( refs1.equals( refs0 ), "exact copies of Referrals should be equal" );
    }


    /**
     * Tests to make sure to get equal hashCode for the same exact object.
     */
    @Test
    public void testHashCodeSameObject()
    {
        ReferralImpl refs = new ReferralImpl();
        assertTrue( refs.hashCode() == refs.hashCode() );
    }


    /**
     * Tests to make sure to get equal hashCode for two objects that are the
     * same exact copy of one another.
     */
    @Test
    public void testHashCodeExactCopy()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        refs1.addLdapUrl( "ldap://blah2" );
        assertTrue( refs0.hashCode() == refs1.hashCode() );
    }


    /**
     * Tests to make sure to get equal hashCode for two objects that are the
     * same exact copy of one another but there are redundant entries.
     */
    @Test
    public void testHashCodeExactCopyWithRedundancy()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        refs0.addLdapUrl( "ldap://blah2" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        refs1.addLdapUrl( "ldap://blah2" );
        refs1.addLdapUrl( "ldap://blah2" );
        assertTrue( refs0.hashCode() == refs1.hashCode() );
    }


    /**
     * Tests to make sure the equals method works for two objects that are the
     * not exact copies of one another but have the same number of URLs.
     */
    @Test
    public void testEqualsSameNumberButDifferentUrls()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        refs0.addLdapUrl( "ldap://blah3" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        refs1.addLdapUrl( "ldap://blah2" );
        refs1.addLdapUrl( "ldap://blah4" );
        assertFalse( refs0.equals( refs1 ), "Referrals should not be equal" );
        assertFalse( refs1.equals( refs0 ), "Referrals should not be equal" );
    }


    /**
     * Tests to make sure the equals method works for two objects that are the
     * not exact copies of one another and one has a subset of the urls of the
     * other.
     */
    @Test
    public void testEqualsSubset()
    {
        ReferralImpl refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://blah0" );
        refs0.addLdapUrl( "ldap://blah1" );
        refs0.addLdapUrl( "ldap://blah2" );
        refs0.addLdapUrl( "ldap://blah3" );
        ReferralImpl refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://blah0" );
        refs1.addLdapUrl( "ldap://blah1" );
        assertFalse( refs0.equals( refs1 ), "Referrals should not be equal" );
        assertFalse( refs1.equals( refs0 ), "Referrals should not be equal" );
    }


    @Test
    public void testEqualsDifferentImpls()
    {
        Referral refs0 = new Referral()
        {
            public Collection<String> getLdapUrls()
            {
                return Collections.emptyList();
            }


            public void addLdapUrl( String url )
            {
            }


            public void removeLdapUrl( String url )
            {
            }


            public void addLdapUrlBytes( byte[] urlBytes )
            {
            }


            public Collection<byte[]> getLdapUrlsBytes()
            {
                return null;
            }


            public int getReferralLength()
            {
                return 0;
            }


            public void setReferralLength( int referralLength )
            {
            }
        };

        ReferralImpl refs1 = new ReferralImpl();

        assertFalse( refs0.equals( refs1 ), 
            "Object.equals() in effect because we did not redefine equals for the new impl above" );
        assertTrue( refs1.equals( refs0 ), 
            "Empty Referrals should be equal even if they are different implementation classes" );
    }
}
