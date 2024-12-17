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

import org.apache.directory.api.ldap.aci.protectedItem.MaxImmSubItem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Unit tests class ProtectedItem.MaxImmSub.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ProtectedItem_MaxImmSubTest
{
    MaxImmSubItem maxValueCountA;
    MaxImmSubItem maxValueCountACopy;
    MaxImmSubItem maxValueCountB;
    MaxImmSubItem maxValueCountC;


    /**
     * Initialize name instances
     * 
     * @throws Exception if the setup failed
     */
    @BeforeEach
    public void initNames() throws Exception
    {
        MaxImmSubItem misA = new MaxImmSubItem( 1 );
        MaxImmSubItem misB = new MaxImmSubItem( 1 );
        MaxImmSubItem misC = new MaxImmSubItem( 2 );

        maxValueCountA = misA;
        maxValueCountACopy = misA;
        maxValueCountB = misB;
        maxValueCountC = misC;
    }


    @Test
    public void testEqualsNull() throws Exception
    {
        assertFalse( maxValueCountA.equals( null ) );
    }


    @Test
    public void testEqualsReflexive() throws Exception
    {
        assertEquals( maxValueCountA, maxValueCountA );
    }


    @Test
    public void testHashCodeReflexive() throws Exception
    {
        assertEquals( maxValueCountA.hashCode(), maxValueCountA.hashCode() );
    }


    @Test
    public void testEqualsSymmetric() throws Exception
    {
        assertEquals( maxValueCountA, maxValueCountACopy );
        assertEquals( maxValueCountACopy, maxValueCountA );
    }


    @Test
    public void testHashCodeSymmetric() throws Exception
    {
        assertEquals( maxValueCountA.hashCode(), maxValueCountACopy.hashCode() );
        assertEquals( maxValueCountACopy.hashCode(), maxValueCountA.hashCode() );
    }


    @Test
    public void testEqualsTransitive() throws Exception
    {
        assertEquals( maxValueCountA, maxValueCountACopy );
        assertEquals( maxValueCountACopy, maxValueCountB );
        assertEquals( maxValueCountA, maxValueCountB );
    }


    @Test
    public void testHashCodeTransitive() throws Exception
    {
        assertEquals( maxValueCountA.hashCode(), maxValueCountACopy.hashCode() );
        assertEquals( maxValueCountACopy.hashCode(), maxValueCountB.hashCode() );
        assertEquals( maxValueCountA.hashCode(), maxValueCountB.hashCode() );
    }


    @Test
    public void testNotEqualDiffValue() throws Exception
    {
        assertFalse( maxValueCountA.equals( maxValueCountC ) );
        assertFalse( maxValueCountC.equals( maxValueCountA ) );
    }
}
