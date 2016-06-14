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
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * TestCase for the methods of the DeleteRequestImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class DeleteRequestImplTest
{
    private static final Map<String, Control> EMPTY_CONTROL_MAP = new HashMap<String, Control>();


    /**
     * Tests the same object reference for equality.
     */
    @Test
    public void testEqualsSameObj()
    {
        DeleteRequestImpl req = new DeleteRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.equals( req ) );
    }


    /**
     * Tests for equality using exact copies.
     */
    @Test
    public void testEqualsExactCopy() throws LdapException
    {
        DeleteRequestImpl req0 = new DeleteRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        DeleteRequestImpl req1 = new DeleteRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        assertTrue( req0.equals( req1 ) );
    }


    /**
     * Tests the same object reference for equal hashCode.
     */
    @Test
    public void testHashCodeSameObj()
    {
        DeleteRequestImpl req = new DeleteRequestImpl();
        req.setMessageId( 5 );
        assertTrue( req.hashCode() == req.hashCode() );
    }


    /**
     * Tests for equal hashCode using exact copies.
     */
    @Test
    public void testHashCodeExactCopy() throws LdapException
    {
        DeleteRequestImpl req0 = new DeleteRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        DeleteRequestImpl req1 = new DeleteRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        assertTrue( req0.hashCode() == req1.hashCode() );
    }


    /**
     * Test for inequality when only the IDs are different.
     */
    @Test
    public void testNotEqualDiffId() throws LdapException
    {
        DeleteRequestImpl req0 = new DeleteRequestImpl();
        req0.setMessageId( 7 );
        req0.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        DeleteRequestImpl req1 = new DeleteRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Test for inequality when only the Dn names are different.
     */
    @Test
    public void testNotEqualDiffName() throws LdapException
    {
        DeleteRequestImpl req0 = new DeleteRequestImpl();
        req0.setMessageId( 5 );
        req0.setName( new Dn( "uid=akarasulu,dc=example,dc=com" ) );

        DeleteRequestImpl req1 = new DeleteRequestImpl();
        req1.setMessageId( 5 );
        req1.setName( new Dn( "cn=admin,dc=example,dc=com" ) );

        assertFalse( req0.equals( req1 ) );
    }


    /**
     * Tests for equality even when another DeleteRequest implementation is
     * used.
     */
    @Test
    public void testEqualsDiffImpl()
    {
        DeleteRequest req0 = new DeleteRequest()
        {
            public Dn getName()
            {
                return null;
            }


            public DeleteRequest setName( Dn name )
            {
                return this;
            }


            public MessageTypeEnum getResponseType()
            {
                return MessageTypeEnum.DEL_RESPONSE;
            }


            public boolean hasResponse()
            {
                return true;
            }


            public MessageTypeEnum getType()
            {
                return MessageTypeEnum.DEL_REQUEST;
            }


            public Map<String, Control> getControls()
            {
                return EMPTY_CONTROL_MAP;
            }


            public DeleteRequest addControl( Control control )
            {
                return this;
            }


            public DeleteRequest removeControl( Control control )
            {
                return this;
            }


            public int getMessageId()
            {
                return 5;
            }


            public Object get( Object key )
            {
                return null;
            }


            public Object put( Object key, Object value )
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


            public DeleteRequest addAbandonListener( AbandonListener listener )
            {
                return this;
            }


            public DeleteResponse getResultResponse()
            {
                return null;
            }


            public DeleteRequest addAllControls( Control[] controls )
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


            public DeleteRequest setMessageId( int messageId )
            {
                return this;
            }
        };

        DeleteRequestImpl req1 = new DeleteRequestImpl();
        req1.setMessageId( 5 );
        assertTrue( req1.equals( req0 ) );
    }
}
