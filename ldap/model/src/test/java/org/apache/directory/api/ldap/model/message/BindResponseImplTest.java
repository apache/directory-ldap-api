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
package org.apache.directory.api.ldap.model.message;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Tests the methods of the BindResponseImpl class.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 *         $Rev: 946353 $
 */
@Execution(ExecutionMode.CONCURRENT)
public class BindResponseImplTest
{
    private static final byte[] PASSWORD = Strings.getBytesUtf8( "password" );


    /**
     * Tests to make sure the same object returns true with equals().
     */
    @Test
    public void testEqualsSameObj()
    {
        BindResponseImpl resp = new BindResponseImpl( 1 );
        assertTrue( resp.equals( resp ), "same object should be equal" );
    }


    /**
     * Tests to make sure newly created objects with same id are equal.
     */
    @Test
    public void testEqualsNewWithSameId()
    {
        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        BindResponseImpl resp1 = new BindResponseImpl( 1 );
        assertTrue( resp0.equals( resp1 ), "default copy with same id should be equal" );
        assertTrue( resp1.equals( resp0 ), "default copy with same id should be equal" );
    }


    /**
     * Tests to make sure the same object has the same hashCode.
     */
    @Test
    public void testHashCodeSameObj()
    {
        BindResponseImpl resp = new BindResponseImpl( 1 );
        assertTrue( resp.hashCode() == resp.hashCode() );
    }


    /**
     * Tests to make sure newly created objects with same id have the same hashCode.
     */
    @Test
    public void testHashCodeNewWithSameId()
    {
        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        BindResponseImpl resp1 = new BindResponseImpl( 1 );
        assertTrue( resp1.hashCode() == resp0.hashCode() );
    }


    /**
     * Tests to make sure newly created objects with same different id are not
     * equal.
     */
    @Test
    public void testNotEqualsNewWithDiffId()
    {
        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        BindResponseImpl resp1 = new BindResponseImpl( 2 );
        assertFalse( resp0.equals( resp1 ), "different id objects should not be equal" );
        assertFalse( resp1.equals( resp0 ), "different id objects should not be equal" );
    }


    /**
     * Tests to make sure newly created objects with same different saslCreds
     * are not equal.
     */
    @Test
    public void testNotEqualsNewWithDiffSaslCreds()
    {
        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        resp0.setServerSaslCreds( new byte[2] );
        BindResponseImpl resp1 = new BindResponseImpl( 1 );
        resp1.setServerSaslCreds( new byte[3] );
        assertFalse( resp0.equals( resp1 ), "different serverSaslCreds objects should not be equal" );
        assertFalse( resp1.equals( resp0 ), "different serverSaslCreds objects should not be equal" );
    }


    /**
     * Tests for equality of two fully loaded identical BindResponse PDUs.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testEqualsWithTheWorks() throws LdapException
    {
        LdapResultImpl r0 = new LdapResultImpl();
        LdapResultImpl r1 = new LdapResultImpl();

        r0.setDiagnosticMessage( "blah blah blah" );
        r1.setDiagnosticMessage( "blah blah blah" );

        r0.setMatchedDn( new Dn( "dc=example,dc=com" ) );
        r1.setMatchedDn( new Dn( "dc=example,dc=com" ) );

        r0.setResultCode( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        r1.setResultCode( ResultCodeEnum.TIME_LIMIT_EXCEEDED );

        Referral refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://someserver.com" );
        refs0.addLdapUrl( "ldap://anotherserver.org" );

        Referral refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://someserver.com" );
        refs1.addLdapUrl( "ldap://anotherserver.org" );

        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        BindResponseImpl resp1 = new BindResponseImpl( 1 );

        resp0.setServerSaslCreds( PASSWORD );
        resp1.setServerSaslCreds( PASSWORD );

        assertTrue( resp0.equals( resp1 ), "loaded carbon copies should be equal" );
        assertTrue( resp1.equals( resp0 ), "loaded carbon copies should be equal" );
    }


    /**
     * Tests for equal hashCode of two fully loaded identical BindResponse PDUs.
     * 
     * @throws LdapException If the test failed
     */
    @Test
    public void testHashCodeWithTheWorks() throws LdapException
    {
        LdapResultImpl r0 = new LdapResultImpl();
        LdapResultImpl r1 = new LdapResultImpl();

        r0.setDiagnosticMessage( "blah blah blah" );
        r1.setDiagnosticMessage( "blah blah blah" );

        r0.setMatchedDn( new Dn( "dc=example,dc=com" ) );
        r1.setMatchedDn( new Dn( "dc=example,dc=com" ) );

        r0.setResultCode( ResultCodeEnum.TIME_LIMIT_EXCEEDED );
        r1.setResultCode( ResultCodeEnum.TIME_LIMIT_EXCEEDED );

        Referral refs0 = new ReferralImpl();
        refs0.addLdapUrl( "ldap://someserver.com" );
        refs0.addLdapUrl( "ldap://anotherserver.org" );

        Referral refs1 = new ReferralImpl();
        refs1.addLdapUrl( "ldap://someserver.com" );
        refs1.addLdapUrl( "ldap://anotherserver.org" );

        BindResponseImpl resp0 = new BindResponseImpl( 1 );
        BindResponseImpl resp1 = new BindResponseImpl( 1 );

        resp0.setServerSaslCreds( PASSWORD );
        resp1.setServerSaslCreds( PASSWORD );

        assertTrue( resp0.hashCode() == resp1.hashCode() );
    }
}
