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
package org.apache.directory.api.ldap.aci.protectedItem;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.apache.directory.api.ldap.model.filter.SubstringNode;
import org.apache.directory.api.ldap.model.filter.UndefinedNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Unit tests class ClassesItem.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ClassesItemTest
{
    ClassesItem classesItemA;
    ClassesItem classesItemACopy;
    ClassesItem classesItemB;
    ClassesItem classesItemC;


    /**
     * Initialize classesItem instances
     * 
     * @throws Exception if the setup failed
     */
    @BeforeEach
    public void initNames() throws Exception
    {
        classesItemA = new ClassesItem( new SubstringNode( "aa" ) );
        classesItemACopy = new ClassesItem( new SubstringNode( "aa" ) );
        classesItemB = new ClassesItem( new SubstringNode( "aa" ) );
        classesItemC = new ClassesItem( new SubstringNode( "cc" ) );
    }


    @Test
    public void testEqualsNotInstanceOf() throws Exception
    {
        assertFalse( classesItemA.equals( UndefinedNode.UNDEFINED_NODE ) );
    }


    @Test
    public void testEqualsNull() throws Exception
    {
        assertFalse( classesItemA.equals( null ) );
    }


    @Test
    public void testEqualsReflexive() throws Exception
    {
        assertEquals( classesItemA, classesItemA );
    }


    @Test
    public void testHashCodeReflexive() throws Exception
    {
        assertEquals( classesItemA.hashCode(), classesItemA.hashCode() );
    }


    @Test
    public void testEqualsSymmetric() throws Exception
    {
        assertEquals( classesItemA, classesItemACopy );
        assertEquals( classesItemACopy, classesItemA );
    }


    @Test
    public void testHashCodeSymmetric() throws Exception
    {
        assertEquals( classesItemA.hashCode(), classesItemACopy.hashCode() );
        assertEquals( classesItemACopy.hashCode(), classesItemA.hashCode() );
    }


    @Test
    public void testEqualsTransitive() throws Exception
    {
        assertEquals( classesItemA, classesItemACopy );
        assertEquals( classesItemACopy, classesItemB );
        assertEquals( classesItemA, classesItemB );
    }


    @Test
    public void testHashCodeTransitive() throws Exception
    {
        assertEquals( classesItemA.hashCode(), classesItemACopy.hashCode() );
        assertEquals( classesItemACopy.hashCode(), classesItemB.hashCode() );
        assertEquals( classesItemA.hashCode(), classesItemB.hashCode() );
    }


    @Test
    public void testNotEqualDiffValue() throws Exception
    {
        assertFalse( classesItemA.equals( classesItemC ) );
        assertFalse( classesItemC.equals( classesItemA ) );
    }
}
