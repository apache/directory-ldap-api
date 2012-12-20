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
package org.apache.directory.api.ldap.aci.protectedItem;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.util.HashSet;
import java.util.Set;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;

import org.apache.directory.api.ldap.aci.protectedItem.AttributeValueItem;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.filter.UndefinedNode;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;


/**
 * Unit tests class AttributeValueItem.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AttributeValueItemTest
{
    AttributeValueItem attributeValueItemA;
    AttributeValueItem attributeValueItemACopy;
    AttributeValueItem attributeValueItemB;
    AttributeValueItem attributeValueItemC;
    AttributeValueItem attributeValueItemD;
    Set<Attribute> attributeA;
    Set<Attribute> attributeB;
    Set<Attribute> attributeC;
    Set<Attribute> attributeD;


    /**
     * Initialize maxValueCountItem instances
     */
    @Before
    public void initNames() throws Exception
    {
        attributeA = new HashSet<Attribute>();
        attributeA.add( new DefaultAttribute( "aa", "aa" ) );
        attributeA.add( new DefaultAttribute( "aa", "bb" ) );
        attributeA.add( new DefaultAttribute( "aa", "cc" ) );
        // Sets aren't ordered, so adding order must not matter
        attributeB = new HashSet<Attribute>();
        attributeB.add( new DefaultAttribute( "aa", "bb" ) );
        attributeB.add( new DefaultAttribute( "aa", "cc" ) );
        attributeB.add( new DefaultAttribute( "aa", "aa" ) );
        attributeC = new HashSet<Attribute>();
        attributeC.add( new DefaultAttribute( "aa", "aa" ) );
        attributeC.add( new DefaultAttribute( "bb", "bb" ) );
        attributeC.add( new DefaultAttribute( "aa", "cc" ) );
        attributeD = new HashSet<Attribute>();
        attributeD.add( new DefaultAttribute( "aa", "aa" ) );
        attributeD.add( new DefaultAttribute( "aa", "bb" ) );
        attributeD.add( new DefaultAttribute( "aa", "dd" ) );
        attributeValueItemA = new AttributeValueItem( attributeA );
        attributeValueItemACopy = new AttributeValueItem( attributeA );
        attributeValueItemB = new AttributeValueItem( attributeB );
        attributeValueItemC = new AttributeValueItem( attributeC );
        attributeValueItemD = new AttributeValueItem( attributeD );
    }


    @Test
    public void testEqualsNotInstanceOf() throws Exception
    {
        assertFalse( attributeValueItemA.equals( UndefinedNode.UNDEFINED_NODE ) );
    }


    @Test
    public void testEqualsNull() throws Exception
    {
        assertFalse( attributeValueItemA.equals( null ) );
    }


    @Test
    public void testEqualsReflexive() throws Exception
    {
        assertEquals( attributeValueItemA, attributeValueItemA );
    }


    @Test
    public void testHashCodeReflexive() throws Exception
    {
        assertEquals( attributeValueItemA.hashCode(), attributeValueItemA.hashCode() );
    }


    @Test
    public void testEqualsSymmetric() throws Exception
    {
        assertEquals( attributeValueItemA, attributeValueItemACopy );
        assertEquals( attributeValueItemACopy, attributeValueItemA );
    }


    @Test
    public void testHashCodeSymmetric() throws Exception
    {
        assertEquals( attributeValueItemA.hashCode(), attributeValueItemACopy.hashCode() );
        assertEquals( attributeValueItemACopy.hashCode(), attributeValueItemA.hashCode() );
    }


    @Test
    public void testEqualsTransitive() throws Exception
    {
        assertEquals( attributeValueItemA, attributeValueItemACopy );
        assertEquals( attributeValueItemACopy, attributeValueItemB );
        assertEquals( attributeValueItemA, attributeValueItemB );
    }


    @Test
    public void testHashCodeTransitive() throws Exception
    {
        assertEquals( attributeValueItemA.hashCode(), attributeValueItemACopy.hashCode() );
        assertEquals( attributeValueItemACopy.hashCode(), attributeValueItemB.hashCode() );
        assertEquals( attributeValueItemA.hashCode(), attributeValueItemB.hashCode() );
    }


    @Test
    public void testNotEqualDiffValue() throws Exception
    {
        assertFalse( attributeValueItemA.equals( attributeValueItemC ) );
        assertFalse( attributeValueItemC.equals( attributeValueItemA ) );
        assertFalse( attributeValueItemA.equals( attributeValueItemD ) );
        assertFalse( attributeValueItemD.equals( attributeValueItemA ) );
    }
}
