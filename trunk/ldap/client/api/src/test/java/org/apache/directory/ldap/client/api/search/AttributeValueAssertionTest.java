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


import static org.junit.Assert.assertEquals;

import org.junit.Test;


/**
 * 
 * TODO AttributeValueAssertionTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributeValueAssertionTest
{
    @Test
    public void testApproximatelyEqual()
    {
        assertEquals( "(objectClass~=person)",
            AttributeValueAssertionFilter.approximatelyEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid~=admin)",
            AttributeValueAssertionFilter.approximatelyEqual( "uid", "admin" )
                .build().toString() );
    }


    @Test
    public void testEqual()
    {
        assertEquals( "(objectClass=person)",
            AttributeValueAssertionFilter.equal( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid=admin)",
            AttributeValueAssertionFilter.equal( "uid", "admin" )
                .build().toString() );
        assertEquals( "(cn=lu\\2A)",
            AttributeValueAssertionFilter.equal( "cn", "lu*" )
                .build().toString() );
    }


    @Test
    public void testGreaterThanOrEqual()
    {
        assertEquals( "(objectClass>=person)",
            AttributeValueAssertionFilter.greaterThanOrEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid>=admin)",
            AttributeValueAssertionFilter.greaterThanOrEqual( "uid", "admin" )
                .build().toString() );
    }


    @Test
    public void testLessThanOrEqual()
    {
        assertEquals( "(objectClass<=person)",
            AttributeValueAssertionFilter.lessThanOrEqual( "objectClass", "person" )
                .build().toString() );
        assertEquals( "(uid<=admin)",
            AttributeValueAssertionFilter.lessThanOrEqual( "uid", "admin" )
                .build().toString() );
    }
}
