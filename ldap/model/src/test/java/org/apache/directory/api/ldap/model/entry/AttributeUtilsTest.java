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
package org.apache.directory.api.ldap.model.entry;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.util.Strings;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * A test case for the AttributeUtils methods 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class AttributeUtilsTest
{

    byte[] byteArrayA;
    byte[] byteArrayACopy;
    byte[] byteArrayB;
    byte[] byteArrayC;


    /**
     * Initialize name instances
     * 
     * @throws Exception If the setup failed
     */
    @BeforeEach
    public void initNames() throws Exception
    {
        byte[] b = Strings.getBytesUtf8( "aa" );
        byteArrayA = b;
        byteArrayACopy = b;
        byteArrayB = Strings.getBytesUtf8( "aa" );
        byteArrayC = Strings.getBytesUtf8( "cc" );
    }


    /**
     * Test a addModification applied to an empty entry
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyAddModificationToEmptyEntry() throws LdapException
    {
        Entry entry = new DefaultEntry();
        Attribute attr = new DefaultAttribute( "cn", "test" );
        Modification modification = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );
        assertEquals( attr, entry.get( "cn" ) );
    }


    /**
     * Test a addModification applied to an entry 
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyAddModificationToEntry() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.add( "dc", "apache" );
        assertEquals( 1, entry.size() );

        Attribute attr = new DefaultAttribute( "cn", "test" );
        Modification modification = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );

        AttributeUtils.applyModification( entry, modification );
        assertNotNull( entry.get( "cn" ) );
        assertEquals( 2, entry.size() );
        assertEquals( attr, entry.get( "cn" ) );
    }


    /**
     * Test a addModification applied to an entry with the same attribute
     * but with another value 
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyAddModificationToEntryWithValues() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "apache" );
        assertEquals( 1, entry.size() );

        Attribute attr = new DefaultAttribute( "cn", "test" );
        Modification modification = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );

        Attribute attribute = entry.get( "cn" );

        assertTrue( attribute.size() != 0 );

        Set<String> expectedValues = new HashSet<String>();
        expectedValues.add( "apache" );
        expectedValues.add( "test" );

        for ( Value value : attribute )
        {
            String valueStr = value.getString();

            assertTrue( expectedValues.contains( valueStr ) );

            expectedValues.remove( valueStr );
        }

        assertEquals( 0, expectedValues.size() );
    }


    /**
     * Test a addModification applied to an entry with the same attribute
     * and the same value 
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyAddModificationToEntryWithSameValue() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "test", "apache" );
        assertEquals( 1, entry.size() );

        Attribute attr = new DefaultAttribute( "cn", "test" );
        Modification modification = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );

        Attribute cnAttr = entry.get( "cn" );

        assertTrue( cnAttr.size() != 0 );

        Set<String> expectedValues = new HashSet<String>();
        expectedValues.add( "apache" );
        expectedValues.add( "test" );

        for ( Value value : cnAttr )
        {
            String valueStr = value.getString();

            assertTrue( expectedValues.contains( valueStr ) );

            expectedValues.remove( valueStr );
        }

        assertEquals( 0, expectedValues.size() );
    }


    /**
     * Test the deletion of an attribute into an empty entry
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyRemoveModificationFromEmptyEntry() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Attribute attr = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNull( entry.get( "cn" ) );
        assertEquals( 0, entry.size() );
    }


    /**
     * Test the deletion of an attribute into an entry which does not contain the attribute
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyRemoveModificationFromEntryAttributeNotPresent() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Attribute dc = new DefaultAttribute( "dc", "apache" );
        entry.put( dc );

        Attribute cn = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, cn );

        AttributeUtils.applyModification( entry, modification );

        assertNull( entry.get( "cn" ) );
        assertNotNull( entry.get( "dc" ) );
        assertEquals( 1, entry.size() );
        assertEquals( dc, entry.get( "dc" ) );
    }


    /**
     * Test the deletion of an attribute into an entry which contains the attribute
     * but without the value to be deleted
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyRemoveModificationFromEntryAttributeNotSameValue() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Attribute cn = new DefaultAttribute( "cn", "apache" );
        entry.put( cn );

        Attribute attr = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );

        AttributeUtils.applyModification( entry, modification );

        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );
        assertEquals( cn, entry.get( "cn" ) );
    }


    /**
     * Test the deletion of an attribute into an entry which contains the attribute.
     * 
     * The entry should not contain the attribute after the operation
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyRemoveModificationFromEntrySameAttributeSameValue() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "test" );

        Attribute attr = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );

        AttributeUtils.applyModification( entry, modification );

        assertNull( entry.get( "cn" ) );
        assertEquals( 0, entry.size() );
    }


    /**
     * Test the deletion of an attribute into an entry which contains the attribute
     * with more than one value
     * 
     * The entry should contain the attribute after the operation, but with one less value
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyRemoveModificationFromEntrySameAttributeValues() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "test", "apache" );

        Attribute attr = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );

        AttributeUtils.applyModification( entry, modification );

        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );

        Attribute modifiedAttr = entry.get( "cn" );

        assertTrue( modifiedAttr.size() != 0 );

        boolean isFirst = true;

        for ( Value value : modifiedAttr )
        {
            assertTrue( isFirst );

            isFirst = false;
            assertEquals( "apache", value.getString() );
        }
    }


    /**
     * test the addition by modification of an attribute in an empty entry.
     * 
     * As we are replacing a non existing attribute, it should be added.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyModifyModificationFromEmptyEntry() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Attribute attr = new DefaultAttribute( "cn", "test" );

        Modification modification = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNotNull( entry.get( "cn" ) );
        assertEquals( 1, entry.size() );
    }


    /**
     * Test the replacement by modification of an attribute in an empty entry.
     * 
     * As we are replacing a non existing attribute, it should not change the entry.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyModifyEmptyModificationFromEmptyEntry() throws LdapException
    {
        Entry entry = new DefaultEntry();

        Attribute attr = new DefaultAttribute( "cn" );

        Modification modification = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, attr );
        AttributeUtils.applyModification( entry, modification );
        assertNull( entry.get( "cn" ) );
        assertEquals( 0, entry.size() );
    }


    /**
     * Test the replacement by modification of an attribute in an empty entry.
     * 
     * As we are replacing a non existing attribute, it should not change the entry.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyModifyAttributeModification() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "test" );
        entry.put( "ou", "apache", "acme corp" );

        Attribute newOu = new DefaultAttribute( "ou", "Big Company", "directory" );

        Modification modification = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, newOu );

        AttributeUtils.applyModification( entry, modification );

        assertEquals( 2, entry.size() );

        assertNotNull( entry.get( "cn" ) );
        assertNotNull( entry.get( "ou" ) );

        Attribute modifiedAttr = entry.get( "ou" );

        assertTrue( modifiedAttr.size() != 0 );

        Set<String> expectedValues = new HashSet<String>();
        expectedValues.add( "Big Company" );
        expectedValues.add( "directory" );

        for ( Value value : modifiedAttr )
        {
            String valueStr = value.getString();

            assertTrue( expectedValues.contains( valueStr ) );

            expectedValues.remove( valueStr );
        }

        assertEquals( 0, expectedValues.size() );
    }


    /**
     * Test the removing by modification of an existing attribute in an .
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testApplyModifyModificationRemoveAttribute() throws LdapException
    {
        Entry entry = new DefaultEntry();
        entry.put( "cn", "test" );
        entry.put( "ou", "apache", "acme corp" );

        Attribute newOu = new DefaultAttribute( "ou" );

        Modification modification = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, newOu );

        AttributeUtils.applyModification( entry, modification );

        assertEquals( 1, entry.size() );

        assertNotNull( entry.get( "cn" ) );
        assertNull( entry.get( "ou" ) );
    }
}
