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
package org.apache.directory.api.ldap.model.url;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.api.ldap.model.url.LdapUrl.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the class LdapUrl
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class LdapUrlTest
{
    /**
     * Test a null LdapUrl
     */
    @Test
    public void testLdapUrlNull()
    {
        assertEquals( "ldap:///", new LdapUrl().toString() );
    }


    /**
     * test an empty LdapUrl
     */
    @Test
    public void testDnEmpty() throws LdapURLEncodingException
    {
        assertEquals( "ldap:///", new LdapUrl( "" ).toString() );
    }


    /**
     * test a simple LdapUrl
     */
    @Test
    public void testDnSimple() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:80/", new LdapUrl( "ldap://directory.apache.org:80/" )
            .toString() );
    }


    /**
     * test a LdapUrl host 1
     */
    @Test
    public void testDnWithMinus() throws LdapURLEncodingException
    {
        assertEquals( "ldap://d-a.org:80/", new LdapUrl( "ldap://d-a.org:80/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad port
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnBadPort() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:/" );
    }


    /**
     * test a LdapUrl with a bad port 2
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnBadPort2() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:-1/" );
    }


    /**
     * test a LdapUrl with a bad port 3
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnBadPort3() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:abc/" );
    }


    /**
     * test a LdapUrl with a bad port 4
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnBadPort4() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:65536/" );
    }


    /**
     * test a LdapUrl with no host
     */
    @Test
    public void testDnBadHost1() throws LdapURLEncodingException
    {
        assertEquals( "ldap:///", new LdapUrl( "ldap:///" ).toString() );
    }


    /**
     * test a LdapUrl with a bad host 2
     */
    @Test
    public void testDnBadHost2() throws LdapURLEncodingException
    {
        assertEquals( "ldap://./", new LdapUrl( "ldap://./" ).toString() );
    }


    /**
     * test a LdapUrl with a bad host 3
     */
    @Test
    public void testDnBadHost3() throws LdapURLEncodingException
    {
        assertEquals( "ldap://a..b/", new LdapUrl( "ldap://a..b/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad host 4
     */
    @Test
    public void testDnBadHost4() throws LdapURLEncodingException
    {
        assertEquals( "ldap://-/", new LdapUrl( "ldap://-/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad host 5
     */
    @Test
    public void testDnBadHost5() throws LdapURLEncodingException
    {
        assertEquals( "ldap://a.b.c-/", new LdapUrl( "ldap://a.b.c-/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad host 6
     */
    @Test
    public void testDnBadHost6() throws LdapURLEncodingException
    {
        assertEquals( "ldap://a.b.-c/", new LdapUrl( "ldap://a.b.-c/" ).toString() );
        new LdapUrl( "ldap://a.b.-c/" );
    }


    /**
     * test a LdapUrl with a bad host 7
     */
    @Test
    public void testDnBadHost7() throws LdapURLEncodingException
    {
        assertEquals( "ldap://a.-.c/", new LdapUrl( "ldap://a.-.c/" ).toString() );
    }


    /**
     * test a LdapUrl IP host
     */
    @Test
    public void testDnIPV4Host() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.2.3.4/", new LdapUrl( "ldap://1.2.3.4/" ).toString() );
    }


    /**
     * test a LdapUrl IP host and port
     */
    @Test
    public void testDnIPV4HostPort() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.2.3.4:80/", new LdapUrl( "ldap://1.2.3.4:80/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad IP host 1 : we should not get an error, but the host will not be considered 
     * as an IPV4 address
     */
    @Test
    public void testDnBadHostIP1() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.1.1/", new LdapUrl( "ldap://1.1.1/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad IP host 1 : we should not get an error, but the host will not be considered 
     * as an IPV4 address
     */
    @Test
    public void testDnBadHostIP2() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.1.1./", new LdapUrl( "ldap://1.1.1./" ).toString() );
    }


    /**
     * test a LdapUrl with a bad IP host 1 : we should not get an error, but the host will not be considered 
     * as an IPV4 address
     */
    @Test
    public void testDnBadHostIP3() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.1.1.100000/", new LdapUrl( "ldap://1.1.1.100000/" ).toString() );
    }


    /**
     * test a LdapUrl with a bad IP host 4
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnBadHostIP4() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://1.1.1.1.1/" );
    }


    /**
     * test a LdapUrl with a valid host hich is not an IP
     */
    @Test
    public void testDnNotAnIP() throws LdapURLEncodingException
    {
        assertEquals( "ldap://1.1.1.100000.a/", new LdapUrl( "ldap://1.1.1.100000.a/" ).toString() );
    }


    /**
     * test a LdapUrl IPv6 host
     */
    @Test
    public void testDnIPv6Host() throws LdapURLEncodingException
    {
        assertEquals( "ldap://[::]/", new LdapUrl( "ldap://[::]/" ).toString() );
        assertEquals( "ldap://[1::2]/", new LdapUrl( "ldap://[1::2]/" ).toString() );
        assertEquals( "ldap://[abcd:EF01:0234:5678:abcd:EF01:0234:5678]/", new LdapUrl( "ldap://[abcd:EF01:0234:5678:abcd:EF01:0234:5678]/" ).toString() );
        assertEquals( "ldap://[::2]/", new LdapUrl( "ldap://[::2]/" ).toString() );
        assertEquals( "ldap://[1:2::3:4]/", new LdapUrl( "ldap://[1:2::3:4]/" ).toString() );
        assertEquals( "ldap://[1:2:3:4:5:6::]/", new LdapUrl( "ldap://[1:2:3:4:5:6::]/" ).toString() );
    }


    /**
     * test a bad LdapUrl IPv6 host
     * @throws LdapURLEncodingException 
     */
    @Test( expected=LdapURLEncodingException.class )
    public void testDnIPv6BadHost() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://[:]/" );
    }


    /**
     * test a bad LdapUrl IPv6 host
     * @throws LdapURLEncodingException 
     */
    @Test( expected=LdapURLEncodingException.class )
    public void testDnIPv6BadHost2() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://[1::2::3]/" );
    }


    /**
     * test a LdapUrl with valid simpleDN
     */
    @Test
    public void testDnSimpleDN() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example,dc=org/", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example,dc=org/" ).toString() );
    }


    /**
     * test a LdapUrl with valid simpleDN 2
     */
    @Test
    public void testDnSimpleDN2() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example" ).toString() );
    }


    /**
     * test a LdapUrl with a valid encoded Dn
     */
    @Test
    public void testDnSimpleDNEncoded() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example%202,dc=org", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example%202,dc=org" ).toString() );
    }


    /**
     * test a LdapUrl with an invalid Dn
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnInvalidDN() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:389/dc=example%202,dc : org" );
    }


    /**
     * test a LdapUrl with an invalid Dn 2
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testDnInvalidDN2() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:389/dc=example%202,dc = org," );
    }


    /**
     * test a LdapUrl with valid unique attributes
     */
    @Test
    public void testDnUniqueAttribute() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example,dc=org?ou", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example,dc=org?ou" ).toString() );
    }


    /**
     * test a LdapUrl with valid attributes
     */
    @Test
    public void testDnAttributes() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example,dc=org?ou,objectclass,dc", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example,dc=org?ou,objectclass,dc" ).toString() );
    }


    /**
     * test a LdapUrl with valid duplicated attributes
     */
    @Test
    public void testDnDuplicatedAttributes() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/dc=example,dc=org?ou,dc", new LdapUrl(
            "ldap://directory.apache.org:389/dc=example,dc=org?ou,dc,ou" ).toString() );
    }


    /**
     * test a LdapUrl with invalid attributes
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testLdapInvalideAttributes() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://directory.apache.org:389/dc=example,dc=org?ou=,dc" );
    }


    /**
     * test a LdapUrl with attributes but no Dn
     */
    @Test
    public void testLdapNoDNAttributes() throws LdapURLEncodingException
    {
        assertEquals( "ldap://directory.apache.org:389/?ou,dc",
            new LdapUrl( "ldap://directory.apache.org:389/?ou,dc" ).toString() );
    }


    /**
     * test 1 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_1() throws LdapURLEncodingException
    {
        assertEquals( "ldap:///o=University%20of%20Michigan,c=US", new LdapUrl(
            "ldap:///o=University%20of%20Michigan,c=US" ).toString() );
    }


    /**
     * test 2 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_2() throws LdapURLEncodingException
    {
        assertEquals( "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US", new LdapUrl(
            "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US" ).toString() );
    }


    /**
     * test 3 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_3() throws LdapURLEncodingException
    {
        assertEquals( "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US?postalAddress", new LdapUrl(
            "ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US?postalAddress" ).toString() );
    }


    /**
     * test 4 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_4() throws LdapURLEncodingException
    {
        assertEquals( "ldap://host.com:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)",
            new LdapUrl( "ldap://host.com:6666/o=University%20of%20Michigan,c=US??sub?(cn=Babs%20Jensen)" ).toString() );
    }


    /**
     * test 5 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_5() throws LdapURLEncodingException
    {
        assertEquals( "ldap://ldap.itd.umich.edu/c=GB?objectClass?one", new LdapUrl(
            "ldap://ldap.itd.umich.edu/c=GB?objectClass?one" ).toString() );
    }


    /**
     * test 6 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_6() throws LdapURLEncodingException
    {
        assertEquals( "ldap://ldap.question.com/o=Question%3F,c=US?mail", new LdapUrl(
            "ldap://ldap.question.com/o=Question%3f,c=US?mail" ).toString() );
    }


    /**
     * test 7 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_7() throws LdapURLEncodingException
    {
        assertEquals( "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5C00%5C00%5C00%5C04)", new LdapUrl(
            "ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)" ).toString() );
    }


    /**
     * test 8 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_8() throws LdapURLEncodingException
    {
        assertEquals( "ldap:///??sub??bindname=cn=Manager%2co=Foo", new LdapUrl(
            "ldap:///??sub??bindname=cn=Manager%2co=Foo" ).toString() );
    }


    /**
     * test 9 from RFC 2255 LdapUrl
     */
    @Test
    public void testLdapRFC2255_9() throws LdapURLEncodingException
    {
        assertEquals( "ldap:///??sub??!bindname=cn=Manager%2co=Foo", new LdapUrl(
            "ldap:///??sub??!bindname=cn=Manager%2co=Foo" ).toString() );
    }


    /**
     * test an empty ldaps:// LdapUrl
     */
    @Test
    public void testDnEmptyLdaps() throws LdapURLEncodingException
    {
        assertEquals( "ldaps:///", new LdapUrl( "ldaps:///" ).toString() );
    }


    /**
     * test an simple ldaps:// LdapUrl
     */
    @Test
    public void testDnSimpleLdaps() throws LdapURLEncodingException
    {
        assertEquals( "ldaps://directory.apache.org:80/", new LdapUrl( "ldaps://directory.apache.org:80/" )
            .toString() );
    }


    /**
     * test the setScheme() method
     */
    @Test
    public void testDnSetScheme() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl();
        assertEquals( "ldap://", url.getScheme() );

        url.setScheme( "invalid" );
        assertEquals( "ldap://", url.getScheme() );

        url.setScheme( "ldap://" );
        assertEquals( "ldap://", url.getScheme() );

        url.setScheme( "ldaps://" );
        assertEquals( "ldaps://", url.getScheme() );

        url.setScheme( null );
        assertEquals( "ldap://", url.getScheme() );
    }


    /**
     * test the setHost() method
     */
    @Test
    public void testDnSetHost() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl();
        assertNull( url.getHost() );

        url.setHost( "ldap.apache.org" );
        assertEquals( "ldap.apache.org", url.getHost() );
        assertEquals( "ldap://ldap.apache.org/", url.toString() );

        url.setHost( null );
        assertNull( url.getHost() );
        assertEquals( "ldap:///", url.toString() );
    }


    /**
     * test the setPort() method
     */
    @Test
    public void testDnSetPort() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl();
        assertEquals( -1, url.getPort() );

        url.setPort( 389 );
        assertEquals( 389, url.getPort() );
        assertEquals( "ldap://:389/", url.toString() );

        url.setPort( 0 );
        assertEquals( -1, url.getPort() );
        assertEquals( "ldap:///", url.toString() );

        url.setPort( 65536 );
        assertEquals( -1, url.getPort() );
        assertEquals( "ldap:///", url.toString() );
    }


    /**
     * test the setDn() method
     */
    @Test
    public void testDnSetDn() throws LdapURLEncodingException, LdapInvalidDnException
    {
        LdapUrl url = new LdapUrl();
        assertNull( url.getDn() );

        Dn dn = new Dn( "dc=example,dc=com" );
        url.setDn( dn );
        assertEquals( dn, url.getDn() );
        assertEquals( "ldap:///dc=example,dc=com", url.toString() );

        url.setDn( null );
        assertNull( url.getDn() );
        assertEquals( "ldap:///", url.toString() );
    }


    /**
     * test the setAttributes() method
     */
    @Test
    public void testDnSetAttributes() throws LdapURLEncodingException, LdapInvalidDnException
    {
        LdapUrl url = new LdapUrl();
        assertNotNull( url.getAttributes() );
        assertTrue( url.getAttributes().isEmpty() );

        List<String> attributes = new ArrayList<String>();
        url.setDn( new Dn( "dc=example,dc=com" ) );

        url.setAttributes( null );
        assertNotNull( url.getAttributes() );
        assertTrue( url.getAttributes().isEmpty() );
        assertEquals( "ldap:///dc=example,dc=com", url.toString() );

        attributes.add( "cn" );
        url.setAttributes( attributes );
        assertNotNull( url.getAttributes() );
        assertEquals( 1, url.getAttributes().size() );
        assertEquals( "ldap:///dc=example,dc=com?cn", url.toString() );

        attributes.add( "userPassword;binary" );
        url.setAttributes( attributes );
        assertNotNull( url.getAttributes() );
        assertEquals( 2, url.getAttributes().size() );
        assertEquals( "ldap:///dc=example,dc=com?cn,userPassword;binary", url.toString() );
    }


    /**
     * test the setScope() method
     */
    @Test
    public void testDnSetScope() throws LdapURLEncodingException, LdapInvalidDnException
    {
        LdapUrl url = new LdapUrl();
        assertEquals( SearchScope.OBJECT, url.getScope() );

        url.setDn( new Dn( "dc=example,dc=com" ) );

        url.setScope( SearchScope.ONELEVEL );
        assertEquals( SearchScope.ONELEVEL, url.getScope() );
        assertEquals( "ldap:///dc=example,dc=com??one", url.toString() );

        url.setScope( SearchScope.SUBTREE );
        assertEquals( SearchScope.SUBTREE, url.getScope() );
        assertEquals( "ldap:///dc=example,dc=com??sub", url.toString() );

        url.setScope( -1 );
        assertEquals( SearchScope.OBJECT, url.getScope() );
        assertEquals( "ldap:///dc=example,dc=com", url.toString() );
    }


    /**
     * test the setFilter() method
     */
    @Test
    public void testDnSetFilter() throws LdapURLEncodingException, LdapInvalidDnException
    {
        LdapUrl url = new LdapUrl();
        assertNull( url.getFilter() );

        url.setDn( new Dn( "dc=example,dc=com" ) );

        url.setFilter( "(objectClass=person)" );
        assertEquals( "(objectClass=person)", url.getFilter() );
        assertEquals( "ldap:///dc=example,dc=com???(objectClass=person)", url.toString() );

        url.setFilter( "(cn=Babs Jensen)" );
        assertEquals( "(cn=Babs Jensen)", url.getFilter() );
        assertEquals( "ldap:///dc=example,dc=com???(cn=Babs%20Jensen)", url.toString() );

        url.setFilter( null );
        assertNull( url.getFilter() );
        assertEquals( "ldap:///dc=example,dc=com", url.toString() );
    }


    /**
     * test a LdapUrl without a scheme
     *
     */
    @Test
    public void testLdapURLNoScheme() throws LdapURLEncodingException
    {
        try
        {
            new LdapUrl( "/ou=system" );
            fail();
        }
        catch ( LdapURLEncodingException luee )
        {
            assertTrue( true );
        }
    }


    /**
     * test a LdapUrl without a host but with a Dn
     *
     */
    @Test
    public void testLdapURLNoHostDN() throws LdapURLEncodingException
    {
        try
        {
            LdapUrl url = new LdapUrl( "ldap:///ou=system" );

            assertEquals( "ldap:///ou=system", url.toString() );

        }
        catch ( LdapURLEncodingException luee )
        {
            fail();
        }
    }


    /**
     * test a LdapUrl with a host, no port, and a Dn
     *
     */
    @Test
    public void testLdapURLHostNoPortDN() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost/ou=system" );

        assertEquals( "ldap://localhost/ou=system", url.toString() );
    }


    /**
     * test a LdapUrl with no host, a port, and a Dn
     *
     */
    @Test(expected = LdapURLEncodingException.class)
    public void testLdapURLNoHostPortDN() throws LdapURLEncodingException
    {
        new LdapUrl( "ldap://:123/ou=system" );

        fail();
    }


    /**
     * test a LdapUrl with no Dn
     *
     */
    @Test
    public void testLdapURLNoDN() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn and no attributes
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrs() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes and no scope
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, no scope and no filter
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScopeNoFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/???" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn and attributes
     *
     */
    @Test
    public void testLdapURLDN() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system" );

        assertEquals( "ldap://localhost:123/ou=system", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn and attributes
     *
     */
    @Test
    public void testLdapURLDNAttrs() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?ou,dc,cn" );

        assertEquals( "ldap://localhost:123/ou=system?ou,dc,cn", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn and attributes
     *
     */
    @Test
    public void testLdapURLNoDNAttrs() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?ou,dc,cn" );

        assertEquals( "ldap://localhost:123/?ou,dc,cn", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes an scope
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??sub" );

        assertEquals( "ldap://localhost:123/??sub", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes an scope base
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeBase() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??base" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes an default scope
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsDefaultScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes an scope
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??sub" );

        assertEquals( "ldap://localhost:123/ou=system??sub", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes an scope base
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeBase() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??base" );

        assertEquals( "ldap://localhost:123/ou=system", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes an default scope
     *
     */
    @Test
    public void testLdapURLDNNoAttrsDefaultScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??" );

        assertEquals( "ldap://localhost:123/ou=system", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes an scope
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?ou,cn?sub" );

        assertEquals( "ldap://localhost:123/?ou,cn?sub", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes an scope base
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeBase() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?ou,cn?base" );

        assertEquals( "ldap://localhost:123/?ou,cn", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes an default scope
     *
     */
    @Test
    public void testLdapURLNoDNAttrsDefaultScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?ou,cn?" );

        assertEquals( "ldap://localhost:123/?ou,cn", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes an scope
     *
     */
    @Test
    public void testLdapURLDNAttrsScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?ou,cn?sub" );

        assertEquals( "ldap://localhost:123/ou=system?ou,cn?sub", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes an scope base
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeBase() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?ou,cn?base" );

        assertEquals( "ldap://localhost:123/ou=system?ou,cn", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes an default scope
     *
     */
    @Test
    public void testLdapURLDNAttrsDefaultScope() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?ou,cn?" );

        assertEquals( "ldap://localhost:123/ou=system?ou,cn", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, no scope and filter
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/???(cn=test)" );

        assertEquals( "ldap://localhost:123/???(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, no scope and filter
     *
     */
    @Test
    public void testLdapURLDNNoAttrsNoScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system???(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system???(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, no scope and filter
     *
     */
    @Test
    public void testLdapURLNoDNAttrsNoScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,ou,dc??(cn=test)" );

        assertEquals( "ldap://localhost:123/?cn,ou,dc??(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a scope and filter
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??sub?(cn=test)" );

        assertEquals( "ldap://localhost:123/??sub?(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a base scope, and filter
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeBaseFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??base?(cn=test)" );

        assertEquals( "ldap://localhost:123/???(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a scope and filter
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,ou,dc?sub?(cn=test)" );

        assertEquals( "ldap://localhost:123/?cn,ou,dc?sub?(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a base scope, and filter
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeBaseFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,ou,dc?base?(cn=test)" );

        assertEquals( "ldap://localhost:123/?cn,ou,dc??(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a scope and filter
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??sub?(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system??sub?(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a base scope, and filter
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeBaseFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??base?(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system???(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, no scope and filter
     *
     */
    @Test
    public void testLdapURLDNAttrsNoScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,dc,ou??(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system?cn,dc,ou??(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a scope and filter
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?sub?(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc?sub?(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a base scope, and filter
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeBaseFilter() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?base?(cn=test)" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc??(cn=test)", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, no scope, no filter and no extension
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScopeNoFilterNoExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/????" );

        assertEquals( "ldap://localhost:123/", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, no scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/????!a=b,!c" );

        assertEquals( "ldap://localhost:123/????!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, no scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsNoScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/???(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/???(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??sub??!a=b,!c" );

        assertEquals( "ldap://localhost:123/??sub??!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a base scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeBaseNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??base??!a=b,!c" );

        assertEquals( "ldap://localhost:123/????!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??sub?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/??sub?(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, no attributes, a base scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNNoAttrsScopeBaseFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/??base?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/???(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, no scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsNoScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou???!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou???!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, no scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsNoScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou??(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou??(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou?sub??!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou?sub??!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a base scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeBaseNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou?base??!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou???!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou?sub?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou?sub?(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with no Dn, some attributes, a base scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLNoDNAttrsScopeBaseFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/?cn,dc,ou?base?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/?cn,dc,ou??(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, no scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsNoScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system????!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system????!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, no scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsNoScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system???(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system???(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??sub??!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system??sub??!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a base scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeBaseNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??base??!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system????!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??sub?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system??sub?(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, no attributes, a base scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNNoAttrsScopeBaseFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system??base?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system???(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, no scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsNoScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc???!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc???!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, no scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsNoScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc??(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc??(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?sub??!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc?sub??!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a base scope, no filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeBaseNoFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?base??!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc???!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?sub?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc?sub?(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * test a LdapUrl with a Dn, some attributes, a base scope, a filter and some extensions
     *
     */
    @Test
    public void testLdapURLDNAttrsScopeBaseFilterExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/ou=system?cn,ou,dc?base?(cn=test)?!a=b,!c" );

        assertEquals( "ldap://localhost:123/ou=system?cn,ou,dc??(cn=test)?!a=b,!c", url.toString() );
    }


    /**
     * Test a LdapUrl with an extension after an empty extension.
     */
    @Test
    public void testLdapURLExtensionAfterEmptyExtension() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/????!a=b,!c,d=e" );

        assertEquals( "ldap://localhost:123/????!a=b,!c,d=e", url.toString() );
    }


    /**
     * Test the extension order of an LdapUrl.
     */
    @Test
    public void testLdapURLExtensionOrder() throws LdapURLEncodingException
    {
        LdapUrl url = new LdapUrl( "ldap://localhost:123/????!a=b,!c,!x,d=e,f=g,!h=i" );

        assertEquals( "ldap://localhost:123/????!a=b,!c,!x,d=e,f=g,!h=i", url.toString() );

        List<Extension> extensions = url.getExtensions();

        assertTrue( extensions.get( 0 ).isCritical() );
        assertEquals( "a", extensions.get( 0 ).getType() );
        assertEquals( "b", extensions.get( 0 ).getValue() );

        assertTrue( extensions.get( 1 ).isCritical() );
        assertEquals( "c", extensions.get( 1 ).getType() );
        assertNull( extensions.get( 1 ).getValue() );

        assertTrue( extensions.get( 2 ).isCritical() );
        assertEquals( "x", extensions.get( 2 ).getType() );
        assertNull( extensions.get( 2 ).getValue() );

        assertFalse( extensions.get( 3 ).isCritical() );
        assertEquals( "d", extensions.get( 3 ).getType() );
        assertEquals( "e", extensions.get( 3 ).getValue() );

        assertFalse( extensions.get( 4 ).isCritical() );
        assertEquals( "f", extensions.get( 4 ).getType() );
        assertEquals( "g", extensions.get( 4 ).getValue() );

        assertTrue( extensions.get( 5 ).isCritical() );
        assertEquals( "h", extensions.get( 5 ).getType() );
        assertEquals( "i", extensions.get( 5 ).getValue() );
    }


    /**
     * Test UTF-8 values in extension values.
     */
    @Test
    public void testLdapURLExtensionWithUtf8Values() throws Exception
    {
        String germanChars = new String(
            new byte[]
                { ( byte ) 0xC3, ( byte ) 0x84, ( byte ) 0xC3, ( byte ) 0x96, ( byte ) 0xC3, ( byte ) 0x9C,
                    ( byte ) 0xC3, ( byte ) 0x9F, ( byte ) 0xC3, ( byte ) 0xA4, ( byte ) 0xC3, ( byte ) 0xB6,
                    ( byte ) 0xC3, ( byte ) 0xBC }, "UTF-8" );

        LdapUrl url1 = new LdapUrl();
        url1.setHost( "localhost" );
        url1.setPort( 123 );
        url1.setDn( Dn.EMPTY_DN );
        url1.getExtensions().add( new Extension( false, "X-CONNECTION-NAME", germanChars ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=%C3%84%C3%96%C3%9C%C3%9F%C3%A4%C3%B6%C3%BC", url1
            .toString() );

        LdapUrl url2 = new LdapUrl(
            "ldap://localhost:123/????X-CONNECTION-NAME=%c3%84%c3%96%c3%9c%c3%9f%c3%a4%c3%b6%c3%bc" );
        assertEquals( germanChars, url1.getExtensionValue( "X-CONNECTION-NAME" ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=%C3%84%C3%96%C3%9C%C3%9F%C3%A4%C3%B6%C3%BC", url2
            .toString() );
    }


    /**
     * Test comma in extension value.
     */
    @Test
    public void testLdapURLExtensionWithCommaValue() throws Exception
    {
        LdapUrl url1 = new LdapUrl();
        url1.setHost( "localhost" );
        url1.setPort( 123 );
        url1.setDn( Dn.EMPTY_DN );
        url1.getExtensions().add( new Extension( false, "X-CONNECTION-NAME", "," ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=%2c", url1.toString() );

        LdapUrl url2 = new LdapUrl( "ldap://localhost:123/????X-CONNECTION-NAME=%2c" );
        assertEquals( ",", url1.getExtensionValue( "X-CONNECTION-NAME" ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=%2c", url2.toString() );
    }


    /**
     * Test with RFC 3986 reserved characters in extension value.
     *
     *   reserved    = gen-delims / sub-delims
     *   gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
     *   sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
     *                 / "*" / "+" / "," / ";" / "="
     *
     * RFC 4516 specifies that '?' and a ',' must be percent encoded.
     *
     */
    @Test
    public void testLdapURLExtensionWithRFC3986ReservedCharsAndRFC4616Exception() throws Exception
    {
        LdapUrl url1 = new LdapUrl();
        url1.setHost( "localhost" );
        url1.setPort( 123 );
        url1.setDn( Dn.EMPTY_DN );
        url1.getExtensions().add( new Extension( false, "X-CONNECTION-NAME", ":/?#[]@!$&'()*+,;=" ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=:/%3F#[]@!$&'()*+%2c;=", url1.toString() );

        LdapUrl url2 = new LdapUrl( "ldap://localhost:123/????X-CONNECTION-NAME=:/%3f#[]@!$&'()*+%2c;=" );
        assertEquals( ":/?#[]@!$&'()*+,;=", url1.getExtensionValue( "X-CONNECTION-NAME" ) );
        assertEquals( "ldap://localhost:123/????X-CONNECTION-NAME=:/%3F#[]@!$&'()*+%2c;=", url2.toString() );
    }


    /**
     * Test with RFC 3986 unreserved characters in extension value.
     *
     *   unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
     */
    @Test
    public void testLdapURLExtensionWithRFC3986UnreservedChars() throws Exception
    {
        LdapUrl url1 = new LdapUrl();
        url1.setHost( "localhost" );
        url1.setPort( 123 );
        url1.setDn( Dn.EMPTY_DN );
        url1.getExtensions().add(
            new Extension( false, "X-CONNECTION-NAME",
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" ) );
        assertEquals(
            "ldap://localhost:123/????X-CONNECTION-NAME=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
            url1.toString() );

        LdapUrl url2 = new LdapUrl(
            "ldap://localhost:123/????X-CONNECTION-NAME=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~" );
        assertEquals( "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~", url1
            .getExtensionValue( "X-CONNECTION-NAME" ) );
        assertEquals(
            "ldap://localhost:123/????X-CONNECTION-NAME=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
            url2.toString() );
    }
}
