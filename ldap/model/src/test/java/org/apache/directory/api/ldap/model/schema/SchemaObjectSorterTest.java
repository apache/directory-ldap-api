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
package org.apache.directory.api.ldap.model.schema;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.util.Strings;
import org.junit.Test;


/**
 * Tests for SchemaObjectSorter.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaObjectSorterTest
{

    private void addAttributeType( List<AttributeType> attributeTypes, String oid, String name, String superiorOid )
    {
        MutableAttributeType at = new MutableAttributeType( oid );
        at.setNames( name );
        at.setSuperiorOid( superiorOid );
        attributeTypes.add( at );
    }


    @Test
    public void testSortAttributeTypesAlreadySorted()
    {
        List<AttributeType> attributeTypes = new ArrayList<AttributeType>();
        addAttributeType( attributeTypes, "1.1.1", "att1", null );
        addAttributeType( attributeTypes, "1.1.2", "att2", "att1" );
        addAttributeType( attributeTypes, "1.1.3", "att3", "att2" );
        addAttributeType( attributeTypes, "1.1.4", "att4", "att3" );
        addAttributeType( attributeTypes, "1.1.5", "att5", "att1" );
        addAttributeType( attributeTypes, "1.1.6", "att6", null );
        addAttributeType( attributeTypes, "1.1.7", "att7", "other" );

        Iterable<AttributeType> sorted = SchemaObjectSorter.hierarchicalOrdered( attributeTypes );
        assertHierarchicalOrderAT( sorted );
    }


    @Test
    public void testSortAttributeTypesShuffled()
    {
        List<String> oids = Arrays.asList( "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7" );
        for ( int i = 0; i < 1000; i++ )
        {
            Collections.shuffle( oids );
            Iterator<String> oidIterator = oids.iterator();

            List<AttributeType> attributeTypes = new ArrayList<AttributeType>();
            addAttributeType( attributeTypes, oidIterator.next(), "att1", null );
            addAttributeType( attributeTypes, oidIterator.next(), "aTT2", "att1" );
            addAttributeType( attributeTypes, oidIterator.next(), "att3", "att2" );
            addAttributeType( attributeTypes, oidIterator.next(), "att4", "atT3" );
            addAttributeType( attributeTypes, oidIterator.next(), "att5", "aTt1" );
            addAttributeType( attributeTypes, oidIterator.next(), "att6", null );
            addAttributeType( attributeTypes, oidIterator.next(), "att7", "other" );

            Iterable<AttributeType> sorted = SchemaObjectSorter.hierarchicalOrdered( attributeTypes );
            assertHierarchicalOrderAT( sorted );
        }
    }


    private void assertHierarchicalOrderAT( Iterable<AttributeType> ordered )
    {
        Iterator<AttributeType> iterator = ordered.iterator();

        String name1 = assertNextSuperiorAT( iterator, null, "other" );
        String name2 = assertNextSuperiorAT( iterator, null, "other", name1 );
        String name3 = assertNextSuperiorAT( iterator, null, "other", name1, name2 );
        String name4 = assertNextSuperiorAT( iterator, null, "other", name1, name2, name3 );
        String name5 = assertNextSuperiorAT( iterator, null, "other", name1, name2, name3, name4 );
        String name6 = assertNextSuperiorAT( iterator, null, "other", name1, name2, name3, name4, name5 );
        assertNextSuperiorAT( iterator, null, "other", name1, name2, name3, name4, name5, name6 );

        assertFalse( iterator.hasNext() );
    }


    private String assertNextSuperiorAT( Iterator<AttributeType> iterator, String... expected )
    {
        assertTrue( iterator.hasNext() );

        AttributeType next = iterator.next();
        String superiorOid = next.getSuperiorOid();
        if(superiorOid != null) {
            superiorOid = Strings.lowerCase( superiorOid );
        }

        if ( !Arrays.asList( expected ).contains( superiorOid ) )
        {
            fail( "Expected that " + Arrays.asList( expected ) + " contains " + superiorOid );
        }

        return Strings.lowerCase( next.getName() );
    }


    @Test(expected = IllegalStateException.class)
    public void testSortAttributeTypesLoop()
    {
        List<AttributeType> attributeTypes = new ArrayList<AttributeType>();
        addAttributeType( attributeTypes, "1.1.1", "att1", "att4" );
        addAttributeType( attributeTypes, "1.1.2", "att2", "att1" );
        addAttributeType( attributeTypes, "1.1.3", "att3", "att2" );
        addAttributeType( attributeTypes, "1.1.4", "att4", "att3" );

        Iterable<AttributeType> sorted = SchemaObjectSorter.hierarchicalOrdered( attributeTypes );
        sorted.iterator().next();
    }


    private void addObjectClass( List<ObjectClass> objectClasses, String oid, String name, String... superiorOid )
    {
        MutableObjectClass oc = new MutableObjectClass( oid );
        oc.setNames( name );
        if ( superiorOid != null )
        {
            oc.setSuperiorOids( Arrays.asList( superiorOid ) );
        }
        objectClasses.add( oc );
    }


    @Test
    public void testSortObjectClassesAlreadySorted()
    {
        List<ObjectClass> objectClasses = new ArrayList<ObjectClass>();
        addObjectClass( objectClasses, "1.2.1", "oc1" );
        addObjectClass( objectClasses, "1.2.2", "OC2", "oc1" );
        addObjectClass( objectClasses, "1.2.3", "oc3", "oC2" );
        addObjectClass( objectClasses, "1.2.4", "oc4" );
        addObjectClass( objectClasses, "1.2.5", "oc5", "Oc2", "oC4" );
        addObjectClass( objectClasses, "1.2.6", "oc6", "other" );

        Iterable<ObjectClass> sorted = SchemaObjectSorter.sortObjectClasses( objectClasses );
        assertHierarchicalOrderOC( sorted );
    }


    @Test
    public void testSortObjectClassesShuffled()
    {
        List<String> oids = Arrays.asList( "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6" );
        for ( int i = 0; i < 1000; i++ )
        {
            Collections.shuffle( oids );
            Iterator<String> oidIterator = oids.iterator();

            List<ObjectClass> objectClasses = new ArrayList<ObjectClass>();
            addObjectClass( objectClasses, oidIterator.next(), "oc1" );
            addObjectClass( objectClasses, oidIterator.next(), "OC2", "oc1" );
            addObjectClass( objectClasses, oidIterator.next(), "oc3", "Oc2" );
            addObjectClass( objectClasses, oidIterator.next(), "oc4" );
            addObjectClass( objectClasses, oidIterator.next(), "oc5", "oC2", "OC4" );
            addObjectClass( objectClasses, oidIterator.next(), "oc6", "other" );

            Iterable<ObjectClass> sorted = SchemaObjectSorter.sortObjectClasses( objectClasses );
            assertHierarchicalOrderOC( sorted );
        }
    }


    private void assertHierarchicalOrderOC( Iterable<ObjectClass> ordered )
    {
        Iterator<ObjectClass> iterator = ordered.iterator();

        String name1 = assertNextSuperiorOC( iterator, null, "other" );
        String name2 = assertNextSuperiorOC( iterator, null, "other", name1 );
        String name3 = assertNextSuperiorOC( iterator, null, "other", name1, name2 );
        String name4 = assertNextSuperiorOC( iterator, null, "other", name1, name2, name3 );
        String name5 = assertNextSuperiorOC( iterator, null, "other", name1, name2, name3, name4 );
        assertNextSuperiorOC( iterator, null, "other", name1, name2, name3, name4, name5 );

        assertFalse( iterator.hasNext() );
    }


    private String assertNextSuperiorOC( Iterator<ObjectClass> iterator, String... expected )
    {
        assertTrue( iterator.hasNext() );

        ObjectClass next = iterator.next();
        List<String> superiorOids = next.getSuperiorOids();
        for ( int i = 0; i < superiorOids.size(); i++ )
        {
            superiorOids.set( i, Strings.lowerCase( superiorOids.get( i ) ) );
        }

        if ( !Arrays.asList( expected ).containsAll( superiorOids ) )
        {
            fail( "Expected that " + Arrays.asList( expected ) + " contains all " + superiorOids );
        }

        return Strings.lowerCase( next.getName() );
    }


    @Test(expected = IllegalStateException.class)
    public void testSortObjectClassesLoop()
    {
        List<ObjectClass> objectClasses = new ArrayList<ObjectClass>();
        addObjectClass( objectClasses, "1.2.1", "oc1", "oc3" );
        addObjectClass( objectClasses, "1.2.2", "oc2", "oc1" );
        addObjectClass( objectClasses, "1.2.3", "oc3", "oc2" );

        Iterable<ObjectClass> sorted = SchemaObjectSorter.sortObjectClasses( objectClasses );
        sorted.iterator().next();
    }

}
