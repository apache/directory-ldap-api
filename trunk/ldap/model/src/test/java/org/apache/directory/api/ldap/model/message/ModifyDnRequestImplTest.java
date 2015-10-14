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

import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * TestCase for the ModifyDnRequestImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ModifyDnRequestImplTest
{
    private static final Map<String, Control> EMPTY_CONTROL_MAP = new HashMap<String, Control>();


    /**
     * Constructs a ModifyDnrequest to test.
     * 
     * @return the request
     */
    private ModifyDnRequestImpl getRequest()
    {
        // Construct the ModifyDn request to test
        ModifyDnRequestImpl request = new ModifyDnRequestImpl();
        request.setMessageId( 45 );
        request.setDeleteOldRdn( true );

        try
        {
            request.setName( new Dn( "dc=admins,dc=apache,dc=org" ) );
            request.setNewRdn( new Rdn( "dc=administrators" ) );
            request.setNewSuperior( new Dn( "dc=groups,dc=apache,dc=org" ) );
        }
        catch ( LdapException ine )
        {
            // do nothing
        }

        return request;
    }


    /**
     * Tests the same object reference for equality.
     */
    @Test
    public void testEqualsSameObj()
    {
        ModifyDnRequestImpl req = new ModifyDnRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.equals( req ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy0()
    {
        ModifyDnRequestImpl req0 = getRequest();
        ModifyDnRequestImpl req1 = getRequest();

        assertTrue( req0.equals( req1 ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy1()
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setNewSuperior( null );
        ModifyDnRequestImpl req1 = getRequest();
        req1.setNewSuperior( null );

        assertTrue( req0.equals( req1 ) );
    }


    /**
    * Tests the same object reference for equal hashCode
    */
    @Test
    public void testHashCodeSameObj()
    {
        ModifyDnRequestImpl req = new ModifyDnRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.hashCode() == req.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy0()
    {
        ModifyDnRequestImpl req0 = getRequest();
        ModifyDnRequestImpl req1 = getRequest();

        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy1()
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setNewSuperior( null );
        ModifyDnRequestImpl req1 = getRequest();
        req1.setNewSuperior( null );

        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Test for inequality when only the IDs are different.
     */
    @Test
    public void testNotEqualDiffId()
    {
        ModifyDnRequestImpl req0 = new ModifyDnRequestImpl();
        req0.setMessageId( 4 );
        ModifyDnRequestImpl req1 = new ModifyDnRequestImpl();
        req1.setMessageId( 5 );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the Dn names are different.
     */
    @Test
    public void testNotEqualDiffName() throws LdapException
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        ModifyDnRequestImpl req1 = getRequest();
        req1.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the newSuperior DNs are different.
     */
    @Test
    public void testNotEqualDiffNewSuperior() throws LdapException
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setNewSuperior( new Dn( "cn=admin,dc=example,dc=com" ) );

        ModifyDnRequestImpl req1 = getRequest();
        req1.setNewSuperior( new Dn( "cn=admin,dc=apache,dc=org" ) );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the delete old Rdn properties is different.
     */
    @Test
    public void testNotEqualDiffDeleteOldRdn()
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setDeleteOldRdn( true );

        ModifyDnRequestImpl req1 = getRequest();
        req1.setDeleteOldRdn( false );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the new Rdn properties are different.
     */
    @Test
    public void testNotEqualDiffNewRdn() throws LdapException
    {
        ModifyDnRequestImpl req0 = getRequest();
        req0.setNewRdn( new Rdn( "cn=admin0" ) );

        ModifyDnRequestImpl req1 = getRequest();
        req1.setNewRdn( new Rdn( "cn=admin1" ) );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Tests for equality even when another BindRequest implementation is used.
     */
    @Test
    public void testEqualsDiffImpl()
    {
        ModifyDnRequest req0 = new ModifyDnRequest()
        {
            public Dn getName()
            {
                try
                {
                    return new Dn( "dc=admins,dc=apache,dc=org" );
                }
                catch ( LdapException ine )
                {
                    // do nothing
                    return null;
                }
            }


            public ModifyDnRequest setName( Dn name )
            {
                return this;
            }


            public Rdn getNewRdn()
            {
                try
                {
                    return new Rdn( "dc=administrators" );
                }
                catch ( LdapException ine )
                {
                    // do nothing
                    return null;
                }
            }


            public ModifyDnRequest setNewRdn( Rdn newRdn )
            {
                return this;
            }


            public boolean getDeleteOldRdn()
            {
                return true;
            }


            public ModifyDnRequest setDeleteOldRdn( boolean deleteOldRdn )
            {
                return this;
            }


            public Dn getNewSuperior()
            {
                try
                {
                    return new Dn( "dc=groups,dc=apache,dc=org" );
                }
                catch ( LdapException ine )
                {
                    // do nothing
                    return null;
                }
            }


            public ModifyDnRequest setNewSuperior( Dn newSuperior )
            {
                return this;
            }


            public boolean isMove()
            {
                return false;
            }


            public MessageTypeEnum getResponseType()
            {
                return MessageTypeEnum.MODIFYDN_RESPONSE;
            }


            public boolean hasResponse()
            {
                return true;
            }


            public MessageTypeEnum getType()
            {
                return MessageTypeEnum.MODIFYDN_REQUEST;
            }


            public Map<String, Control> getControls()
            {
                return EMPTY_CONTROL_MAP;
            }


            public ModifyDnRequest addControl( Control a_control )
            {
                return this;
            }


            public ModifyDnRequest removeControl( Control a_control )
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


            public ModifyDnRequest addAbandonListener( AbandonListener listener )
            {
                return this;
            }


            public ModifyDnResponse getResultResponse()
            {
                return null;
            }


            public ModifyDnRequest addAllControls( Control[] controls )
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


            public ModifyDnRequest setMessageId( int messageId )
            {
                return this;
            }
        };

        ModifyDnRequestImpl req1 = getRequest();
        assertTrue( req1.equals( req0 ) );
    }
}
