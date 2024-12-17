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
package org.apache.directory.api.ldap.aci;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.apache.directory.api.ldap.aci.protectedItem.RangeOfValuesItem;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Unit tests class ProtectedItem.RangeOfValues.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ProtectedItem_RangeOfValuesTest
{
    RangeOfValuesItem rangeOfValuesA;
    RangeOfValuesItem rangeOfValuesACopy;
    RangeOfValuesItem rangeOfValuesB;
    RangeOfValuesItem rangeOfValuesC;


    /**
     * Initialize name instances
     * 
     * @throws Exception if the setup failed
     */
    @BeforeEach
    public void initNames() throws Exception
    {

        ExprNode filterA = FilterParser.parse( "(&(cn=test)(sn=test))" );
        ExprNode filterB = FilterParser.parse( "(&(cn=test)(sn=test))" );
        ExprNode filterC = FilterParser.parse( "(&(cn=sample)(sn=sample))" );

        rangeOfValuesA = new RangeOfValuesItem( filterA );
        rangeOfValuesACopy = new RangeOfValuesItem( filterA );
        rangeOfValuesB = new RangeOfValuesItem( filterB );
        rangeOfValuesC = new RangeOfValuesItem( filterC );
    }


    @Test
    public void testEqualsNull() throws Exception
    {
        assertFalse( rangeOfValuesA.equals( null ) );
    }


    @Test
    public void testEqualsReflexive() throws Exception
    {
        assertEquals( rangeOfValuesA, rangeOfValuesA );
    }


    @Test
    public void testHashCodeReflexive() throws Exception
    {
        assertEquals( rangeOfValuesA.hashCode(), rangeOfValuesA.hashCode() );
    }


    @Test
    public void testEqualsSymmetric() throws Exception
    {
        assertEquals( rangeOfValuesA, rangeOfValuesACopy );
        assertEquals( rangeOfValuesACopy, rangeOfValuesA );
    }


    @Test
    public void testHashCodeSymmetric() throws Exception
    {
        assertEquals( rangeOfValuesA.hashCode(), rangeOfValuesACopy.hashCode() );
        assertEquals( rangeOfValuesACopy.hashCode(), rangeOfValuesA.hashCode() );
    }


    @Test
    public void testEqualsTransitive() throws Exception
    {
        assertEquals( rangeOfValuesA, rangeOfValuesACopy );
        assertEquals( rangeOfValuesACopy, rangeOfValuesB );
        assertEquals( rangeOfValuesA, rangeOfValuesB );
    }


    @Test
    public void testHashCodeTransitive() throws Exception
    {
        assertEquals( rangeOfValuesA.hashCode(), rangeOfValuesACopy.hashCode() );
        assertEquals( rangeOfValuesACopy.hashCode(), rangeOfValuesB.hashCode() );
        assertEquals( rangeOfValuesA.hashCode(), rangeOfValuesB.hashCode() );
    }


    @Test
    public void testNotEqualDiffValue() throws Exception
    {
        assertFalse( rangeOfValuesA.equals( rangeOfValuesC ) );
        assertFalse( rangeOfValuesC.equals( rangeOfValuesA ) );
    }
}
