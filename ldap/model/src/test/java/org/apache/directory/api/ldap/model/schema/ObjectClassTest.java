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
package org.apache.directory.api.ldap.model.schema;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Unit tests class ObjectClass.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class ObjectClassTest
{
    private ObjectClass objectClassA;
    private ObjectClass objectClassACopy;
    private ObjectClass objectClassB;
    private ObjectClass objectClassC;
    private ObjectClass objectClass;


    /**
     * Initialize object class instances
     */
    @BeforeEach
    public void initObjectClasses() throws Exception
    {
        // TODO Create ObjectClasses with more meaningful constructor arguments
        objectClassA = new ObjectClass( "aa" );
        objectClassACopy = new ObjectClass( "aa" );
        objectClassB = new ObjectClass( "aa" );
        objectClassC = new ObjectClass( "cc" );

        objectClass = new ObjectClass( "1.2.3.4" );
        objectClass.setNames( "name1", "name2" );
        objectClass.setDescription( "description" );
        objectClass.setObsolete( false );
        objectClass.setSuperiorOids( Collections.singletonList( "1.3.5.7" ) );
        objectClass.setType( ObjectClassTypeEnum.STRUCTURAL );
        objectClass.setMustAttributeTypeOids( Arrays.asList( "att1", "att2" ) );
        objectClass.setMayAttributeTypeOids( Arrays.asList( "att3", "att4" ) );
    }


    @Test
    public void testEqualsNull() throws Exception
    {
        assertFalse( objectClassA.equals( null ) );
    }


    @Test
    public void testEqualsReflexive() throws Exception
    {
        assertEquals( objectClassA, objectClassA );
    }


    @Test
    public void testHashCodeReflexive() throws Exception
    {
        assertEquals( objectClassA.hashCode(), objectClassA.hashCode() );
    }


    @Test
    public void testEqualsSymmetric() throws Exception
    {
        assertEquals( objectClassA, objectClassACopy );
        assertEquals( objectClassACopy, objectClassA );
    }


    @Test
    public void testHashCodeSymmetric() throws Exception
    {
        assertEquals( objectClassA.hashCode(), objectClassACopy.hashCode() );
        assertEquals( objectClassACopy.hashCode(), objectClassA.hashCode() );
    }


    @Test
    public void testEqualsTransitive() throws Exception
    {
        assertEquals( objectClassA, objectClassACopy );
        assertEquals( objectClassACopy, objectClassB );
        assertEquals( objectClassA, objectClassB );
    }


    @Test
    public void testHashCodeTransitive() throws Exception
    {
        assertEquals( objectClassA.hashCode(), objectClassACopy.hashCode() );
        assertEquals( objectClassACopy.hashCode(), objectClassB.hashCode() );
        assertEquals( objectClassA.hashCode(), objectClassB.hashCode() );
    }


    @Test
    public void testNotEqualDiffValue() throws Exception
    {
        assertFalse( objectClassA.equals( objectClassC ) );
        assertFalse( objectClassC.equals( objectClassA ) );
    }


    @Test
    public void testToString() throws Exception
    {
        String string = objectClass.toString();

        assertNotNull( string );
        assertTrue( string.startsWith( "objectclass (" ) );
        assertTrue( string.contains( " NAME " ) );
        assertTrue( string.contains( "\n\tDESC " ) );
        assertTrue( string.contains( "\n\tSUP " ) );
        assertTrue( string.contains( "\n\tSTRUCTURAL" ) );
        assertTrue( string.contains( "\n\tMUST" ) );
        assertTrue( string.contains( "\n\tMAY" ) );
        assertTrue( string.endsWith( " )" ) );
    }
}
