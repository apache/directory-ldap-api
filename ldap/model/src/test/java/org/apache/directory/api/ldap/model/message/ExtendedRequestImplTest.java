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
package org.apache.directory.api.ldap.model.message;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * TestCase for the ExtendedRequestImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class ExtendedRequestImplTest
{
    /**
     * Tests the same object reference for equality.
     */
    @Test
    public void testEqualsSameObj()
    {
        OpaqueExtendedRequest req = new OpaqueExtendedRequest();
        req.setMessageId( 5 );
        assertTrue( req.equals( req ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy()
    {
        OpaqueExtendedRequest req0 = new OpaqueExtendedRequest();
        req0.setMessageId( 5 );
        req0.setRequestName( "1.1.1.1" );

        OpaqueExtendedRequest req1 = new OpaqueExtendedRequest();
        req1.setMessageId( 5 );
        req1.setRequestName( "1.1.1.1" );

        assertTrue( req0.equals( req1 ) );
        assertTrue( req1.equals( req0 ) );
    }


    /**
     * Tests the same object reference for equal hashCode.
     */
    @Test
    public void testHashCodeSameObj()
    {
        OpaqueExtendedRequest req = new OpaqueExtendedRequest();
        req.setMessageId( 5 );
        assertTrue( req.hashCode() == req.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy()
    {
        OpaqueExtendedRequest req0 = new OpaqueExtendedRequest();
        req0.setMessageId( 5 );
        req0.setRequestName( "1.1.1.1" );

        OpaqueExtendedRequest req1 = new OpaqueExtendedRequest();
        req1.setMessageId( 5 );
        req1.setRequestName( "1.1.1.1" );

        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Test for inequality when only the IDs are different.
     */
    @Test
    public void testNotEqualDiffId()
    {
        OpaqueExtendedRequest req0 = new OpaqueExtendedRequest();
        req0.setMessageId( 7 );
        OpaqueExtendedRequest req1 = new OpaqueExtendedRequest();
        req1.setMessageId( 5 );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the OID is different.
     */
    @Test
    public void testNotEqualDiffOID()
    {
        OpaqueExtendedRequest req0 = new OpaqueExtendedRequest();
        req0.setMessageId( 5 );
        req0.setRequestName( "1.1.1.1" );

        OpaqueExtendedRequest req1 = new OpaqueExtendedRequest();
        req1.setMessageId( 5 );
        req0.setRequestName( "1.2.2.1" );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the Assertion values are different.
     */
    @Test
    public void testNotEqualDiffValue()
    {
        OpaqueExtendedRequest req0 = new OpaqueExtendedRequest();
        req0.setMessageId( 5 );
        req0.setRequestName( "1.1.1.1" );

        OpaqueExtendedRequest req1 = new OpaqueExtendedRequest();
        req1.setMessageId( 5 );
        req0.setRequestName( "1.1.1.1" );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }
}
