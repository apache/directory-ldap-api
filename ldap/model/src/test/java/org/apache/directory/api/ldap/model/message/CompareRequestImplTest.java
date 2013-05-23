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

import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * TestCase for the CompareRequestImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class CompareRequestImplTest
{
    private static final Map<String, Control> EMPTY_CONTROL_MAP = new HashMap<String, Control>();


    /**
     * Tests the same object reference for equality.
     */
    @Test
    public void testEqualsSameObj()
    {
        CompareRequestImpl req = new CompareRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.equals( req ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy() throws LdapException
    {
        CompareRequestImpl req0 = new CompareRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );
        req0.setAttributeId( "objectClass" );
        req0.setAssertionValue( "top" );

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );
        req1.setAttributeId( "objectClass" );
        req1.setAssertionValue( "top" );

        assertTrue( req0.equals( req1 ) );
        assertTrue( req1.equals( req0 ) );
    }


    /**
     * Tests the same object reference for equal hashCode.
     */
    @Test
    public void testHashCodeSameObj()
    {
        CompareRequestImpl req = new CompareRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.hashCode() == req.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy() throws LdapException
    {
        CompareRequestImpl req0 = new CompareRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );
        req0.setAttributeId( "objectClass" );
        req0.setAssertionValue( "top" );

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );
        req1.setAttributeId( "objectClass" );
        req1.setAssertionValue( "top" );

        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Test for inequality when only the IDs are different.
     */
    @Test
    public void testNotEqualDiffId() throws LdapException
    {
        CompareRequestImpl req0 = new CompareRequestImpl();
        req0.setMessageId( 7 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the attributeIds are different.
     */
    @Test
    public void testNotEqualDiffAttributeIds() throws LdapException
    {
        CompareRequestImpl req0 = new CompareRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );
        req0.setAttributeId( "dc" );
        req0.setAssertionValue( "apache.org" );

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );
        req1.setAttributeId( "nisDomain" );
        req1.setAssertionValue( "apache.org" );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Test for inequality when only the Assertion values are different.
     */
    @Test
    public void testNotEqualDiffValue() throws LdapException
    {
        CompareRequestImpl req0 = new CompareRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );
        req0.setAttributeId( "dc" );
        req0.setAssertionValue( "apache.org" );

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=apache,dc=org" ) );
        req1.setAttributeId( "dc" );
        req1.setAssertionValue( "nagoya.apache.org" );

        assertFalse( req0.equals( req1 ) );
        assertFalse( req1.equals( req0 ) );
    }


    /**
     * Tests for equality even when another CompareRequest implementation is
     * used.
     */
    @Test
    public void testEqualsDiffImpl()
    {
        CompareRequest req0 = new CompareRequest()
        {
            public Value<?> getAssertionValue()
            {
                return null;
            }


            public CompareRequest setAssertionValue( String value )
            {
                return this;
            }


            public CompareRequest setAssertionValue( byte[] value )
            {
                return this;
            }


            public String getAttributeId()
            {
                return null;
            }


            public CompareRequest setAttributeId( String attrId )
            {
                return this;
            }


            public Dn getName()
            {
                return null;
            }


            public CompareRequest setName( Dn name )
            {
                return this;
            }


            public MessageTypeEnum getResponseType()
            {
                return MessageTypeEnum.COMPARE_RESPONSE;
            }


            public boolean hasResponse()
            {
                return true;
            }


            public MessageTypeEnum getType()
            {
                return MessageTypeEnum.COMPARE_REQUEST;
            }


            public Map<String, Control> getControls()
            {
                return EMPTY_CONTROL_MAP;
            }


            public CompareRequest addControl( Control a_control )
            {
                return this;
            }


            public CompareRequest removeControl( Control a_control )
            {
                return this;
            }


            public int getMessageId()
            {
                return 5;
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


            public CompareRequest addAbandonListener( AbandonListener listener )
            {
                return this;
            }


            public CompareResponse getResultResponse()
            {
                return null;
            }


            public CompareRequest addAllControls( Control[] controls )
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


            public CompareRequest setMessageId( int messageId )
            {
                return this;
            }
        };

        CompareRequestImpl req1 = new CompareRequestImpl();
        req1.setMessageId( 5 );
        assertTrue( req1.equals( req0 ) );
        assertFalse( req0.equals( req1 ) );
    }
}
