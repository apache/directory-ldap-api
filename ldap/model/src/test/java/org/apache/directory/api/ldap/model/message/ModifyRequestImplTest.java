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


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test case for the ModifyRequestImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ModifyRequestImplTest
{
    private static final Map<String, Control> EMPTY_CONTROL_MAP = new HashMap<String, Control>();


    /**
     * Builds a ModifyRequest for testing purposes.
     * 
     * @return the ModifyRequest to use for tests
     */
    private ModifyRequestImpl getRequest() throws LdapException
    {
        // Construct the Modify request to test
        ModifyRequestImpl req = new ModifyRequestImpl();
        req.setMessageId( 45 );

        try
        {
            req.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );
        }
        catch ( LdapException ne )
        {
            // do nothing
        }

        Attribute attr = new DefaultAttribute( "attr0" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req.addModification( item );

        attr = new DefaultAttribute( "attr1" );
        attr.add( "val3" );
        item = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );
        req.addModification( item );

        attr = new DefaultAttribute( "attr2" );
        attr.add( "val4" );
        attr.add( "val5" );
        item = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, attr );
        req.addModification( item );

        return req;
    }


    /**
     * Tests the same object reference for equality.
     */
    @Test
    public void testEqualsSameObj() throws LdapException
    {
        ModifyRequestImpl req = getRequest();
        assertTrue( req.equals( req ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        ModifyRequestImpl req1 = getRequest();
        assertTrue( req0.equals( req1 ) );
    }


    /**
     * Tests the same object reference for equal hashCode.
     */
    @Test
    public void testHashCodeSameObj() throws LdapException
    {
        ModifyRequestImpl req = getRequest();
        assertTrue( req.hashCode() == req.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        ModifyRequestImpl req1 = getRequest();
        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Test for inequality when only the IDs are different.
     */
    @Test
    public void testNotEqualDiffId()
    {
        ModifyRequestImpl req0 = new ModifyRequestImpl();
        req0.setMessageId( 7 );
        ModifyRequestImpl req1 = new ModifyRequestImpl();
        req1.setMessageId( 5 );
        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the Dn names are different.
     */
    @Test
    public void testNotEqualDiffName()
    {
        try
        {
            ModifyRequestImpl req0 = getRequest();
            req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );
            ModifyRequestImpl req1 = getRequest();
            req1.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );

            assertFalse( req0.equals( req1 ) );
        }
        catch ( LdapException ine )
        {
            // do nothing
        }
    }


    /**
     * Test for inequality when only the mods ops are different.
     */
    @Test
    public void testNotEqualDiffModOps() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        Attribute attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        ModifyRequestImpl req1 = getRequest();
        attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        item = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );
        req0.addModification( item );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the number of mods are different.
     */
    @Test
    public void testNotEqualDiffModCount() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        Attribute attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        ModifyRequestImpl req1 = getRequest();

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the mods attribute Id's are different.
     */
    @Test
    public void testNotEqualDiffModIds() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        Attribute attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        ModifyRequestImpl req1 = getRequest();
        attr = new DefaultAttribute( "attr4" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the mods attribute values are different.
     */
    @Test
    public void testNotEqualDiffModValues() throws LdapException
    {
        ModifyRequestImpl req0 = getRequest();
        Attribute attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        ModifyRequestImpl req1 = getRequest();
        attr = new DefaultAttribute( "attr3" );
        attr.add( "val0" );
        attr.add( "val1" );
        attr.add( "val2" );
        attr.add( "val3" );
        item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
        req0.addModification( item );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Tests for equality even when another BindRequest implementation is used.
     */
    @Test
    public void testEqualsDiffImpl() throws LdapException
    {
        ModifyRequest req0 = new ModifyRequest()
        {
            public Collection<Modification> getModifications()
            {
                List<Modification> list = new ArrayList<Modification>();

                try
                {
                    Attribute attr = new DefaultAttribute( "attr0" );
                    attr.add( "val0" );
                    attr.add( "val1" );
                    attr.add( "val2" );
                    Modification item = new DefaultModification( ModificationOperation.ADD_ATTRIBUTE, attr );
                    list.add( item );

                    attr = new DefaultAttribute( "attr1" );
                    attr.add( "val3" );
                    item = new DefaultModification( ModificationOperation.REMOVE_ATTRIBUTE, attr );
                    list.add( item );

                    attr = new DefaultAttribute( "attr2" );
                    attr.add( "val4" );
                    attr.add( "val5" );
                    item = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, attr );
                    list.add( item );
                }
                catch ( LdapInvalidAttributeValueException liave )
                {
                    // Can't happen
                }

                return list;
            }


            public ModifyRequest addModification( Modification mod )
            {
                return this;
            }


            public ModifyRequest removeModification( Modification mod )
            {
                return this;
            }


            public Dn getName()
            {
                try
                {
                    return new Dn( "cn=admin,dc=apache,dc=org" );
                }
                catch ( Exception e )
                {
                    //do nothing
                    return null;
                }
            }


            public ModifyRequest setName( Dn name )
            {
                return this;
            }


            public MessageTypeEnum getResponseType()
            {
                return MessageTypeEnum.MODIFY_RESPONSE;
            }


            public boolean hasResponse()
            {
                return true;
            }


            public MessageTypeEnum getType()
            {
                return MessageTypeEnum.MODIFY_REQUEST;
            }


            public Map<String, Control> getControls()
            {
                return EMPTY_CONTROL_MAP;
            }


            public ModifyRequest addControl( Control a_control )
            {
                return this;
            }


            public ModifyRequest removeControl( Control a_control )
            {
                return this;
            }


            public int getMessageId()
            {
                return 45;
            }


            public Object get( Object a_key )
            {
                return null;
            }


            public Object put( Object a_key, Object a_value )
            {
                return null;
            }


            public void abandon()
            {
            }


            public boolean isAbandoned()
            {
                return false;
            }


            public ModifyRequest addAbandonListener( AbandonListener listener )
            {
                return this;
            }


            public ModifyResponse getResultResponse()
            {
                return null;
            }


            public ModifyRequest addAllControls( Control[] controls )
            {
                return this;
            }


            public boolean hasControl( String oid )
            {
                return false;
            }


            public Control getControl( String oid )
            {
                return null;
            }


            public ModifyRequest setMessageId( int messageId )
            {
                return this;
            }


            public ModifyRequest addModification( Attribute attr, ModificationOperation modOp )
            {
                return this;
            }


            public ModifyRequest replace( String attributeName )
            {
                return this;
            }


            public ModifyRequest replace( String attributeName, String... attributeValue )
            {
                return this;
            }


            public ModifyRequest replace( String attributeName, byte[]... attributeValue )
            {
                return this;
            }


            public ModifyRequest replace( Attribute attr )
            {
                return this;
            }


            public ModifyRequest add( String attributeName, String... attributeValue )
            {
                return this;
            }


            public ModifyRequest add( String attributeName, byte[]... attributeValue )
            {
                return this;
            }


            public ModifyRequest add( Attribute attr )
            {
                return this;
            }


            public ModifyRequest remove( String attributeName, String... attributeValue )
            {
                return this;
            }


            public ModifyRequest remove( String attributeName, byte[]... attributeValue )
            {
                return this;
            }


            public ModifyRequest remove( Attribute attr )
            {
                return this;
            }


            public ModifyRequest remove( String attributerName )
            {
                return this;
            }
        };

        ModifyRequestImpl req1 = getRequest();
        assertTrue( req1.equals( req0 ) );
    }
}
