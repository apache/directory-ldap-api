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
package org.apache.directory.api.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;


/**
 * Test the class AttributeTypeAndValue
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class AvaTest
{
    private static SchemaManager schemaManager;


    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }


    /**
     * Test a null AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueNull()
    {
        Ava atav = new Ava( schemaManager );
        assertEquals( "", atav.toString() );
        assertEquals( "", atav.getName() );
    }


    /**
     * Test a null type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueNullType() throws LdapException
    {
        try
        {
            new Ava( schemaManager, null, ( String ) null );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }

    }


    /**
     * Test an invalid type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueInvalidType() throws LdapException
    {
        try
        {
            new Ava( schemaManager, "  ", ( String ) null );
            fail();
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * Test a valid type for an AttributeTypeAndValue
     */
    @Test
    public void testAttributeTypeAndValueValidType() throws LdapException
    {
        Ava ava = new Ava( schemaManager, "CN", " " );
        assertEquals( "CN=\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "CN=\\ ", ava.getName() );

        ava = new Ava( schemaManager, "  CN  ", " " );
        assertEquals( "  CN  =\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "  CN  =\\ ", ava.getName() );

        ava = new Ava( schemaManager, "cn", " " );
        assertEquals( "cn=\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "cn=\\ ", ava.getName() );

        ava = new Ava( schemaManager, "  cn  ", " " );
        assertEquals( "  cn  =\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "  cn  =\\ ", ava.getName() );
    }


    /**
     * test an empty AttributeTypeAndValue
     */
    @Test
    public void testAvaEmpty()
    {
        try
        {
            new Ava( schemaManager, "", "" );
            fail( "Should not occurs ... " );
        }
        catch ( LdapException ine )
        {
            assertTrue( true );
        }
    }


    /**
     * test a simple AttributeTypeAndValue : a = b
     */
    @Test
    public void testAvaSimple() throws LdapException
    {
        Ava atav = new Ava( schemaManager, "cn", "b" );
        assertEquals( "cn=b", atav.toString() );
        assertEquals( "2.5.4.3=b", atav.getNormName() );
        assertEquals( "cn=b", atav.getName() );
    }


    /**
     * test a simple AttributeTypeAndValue : a = b
     */
    @Test
    public void testAvaSimpleNorm() throws LdapException
    {
        Ava atav = new Ava( schemaManager, " CommonName ", " This is    a TEST " );
        assertEquals( " CommonName =\\ This is    a TEST\\ ", atav.toString() );
        assertEquals( "2.5.4.3=this is a test", atav.getNormName() );
        assertEquals( " CommonName =\\ This is    a TEST\\ ", atav.getName() );
    }


    /**
     * Compares two equals atavs
     */
    @Test
    public void testEqualsSameAva() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "b" );
        Ava atav2 = new Ava( schemaManager, "cn", "b" );

        assertTrue( atav1.equals( atav2 ) );
    }


    /**
     * Compares two equals atavs but with a type in different case
     */
    @Test
    public void testEqualsUpperCaseAT() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "b" );
        Ava atav2 = new Ava( schemaManager, "CN", "b" );

        assertTrue( atav1.equals( atav2 ) );
    }


    /**
     * Compares two equals atavs but with a type in different case
     */
    @Test
    public void testEqualsSameValues() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "  B  a" );
        Ava atav2 = new Ava( schemaManager, "CN", "b a" );

        assertTrue( atav1.equals( atav2 ) );
    }
    
    
    /**
     * Test the returned values for Ava. \u00E4 is the unicode char for "ä", encoded
     * \C3\A4 in UTF8
     */
    @Test
    public void testAvaValuesNoSchema() throws LdapException
    {
        String errors = null;
        
        Ava ava = new Ava( "OU", "Exemple + Rdn\u00E4 " );
        
        if ( !"ou=Exemple \\+ Rdn\u00E4\\ ".equals( ava.getNormName() ) )
        {
            errors = "\nAva.getNormName fails '" + ava.getNormName() + "'";
        }
        
        if ( !"ou".equals( ava.getNormType() ) )
        {
            errors += "\nAva.getNormType fails '" + ava.getNormType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( ava.getValue().getNormValue().toString() ) )
        {
            errors += "\nAva.getNormValue fails '" + ava.getValue().getNormValue().toString() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\u00E4\\ ".equals( ava.getName() ) )
        {
            errors += "\nAva.getUpName fails '" + ava.getName() + "'";
        }
        
        if ( !"OU".equals( ava.getType() ) )
        {
            errors += "\nAva.getUpType fails '" + ava.getType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( ava.getValue().getString() ) )
        {
            errors += "\nAva.getUpValue fails '" + ava.getValue() .getString() + "'";
        }
        
        if ( !"ou=Exemple \\+ Rdn\u00E4\\ ".equals( ava.normalize() ) )
        {
            errors += "\nAva.normalize fails '" + ava.normalize() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\u00E4\\ ".equals( ava.toString() ) )
        {
            errors += "\nAva.toString fails '" + ava.toString() + "'";
        }
        
        assertEquals( null, errors );
    }
    
    
    /**
     * Test the returned values for a schema aware Ava.
     * \u00E4 is the unicode char for "ä", encoded \C3\A4 in UTF8
     */
    @Test
    public void testAvaValuesSchemaAware() throws LdapException
    {
        String errors = null;
        
        Ava ava = new Ava( schemaManager, "OU", "Exemple + Rdn\u002B " );
        
        if ( !"2.5.4.11=exemple \\+ rdn\\+".equals( ava.getNormName() ) )
        {
            errors = "\nAva.getNormName fails '" + ava.getNormName() + "'";
        }
        
        if ( !"2.5.4.11".equals( ava.getNormType() ) )
        {
            errors += "\nAva.getNormType fails '" + ava.getNormType() + "'";
        }
        
        if ( !"exemple + rdn\u002B".equals( ava.getValue().getNormValue().toString() ) )
        {
            errors += "\nAva.getNormValue fails '" + ava.getValue().getNormValue().toString() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\+\\ ".equals( ava.getName() ) )
        {
            errors += "\nAva.getUpName fails '" + ava.getName() + "'";
        }
        
        if ( !"OU".equals( ava.getType() ) )
        {
            errors += "\nAva.getUpType fails '" + ava.getType() + "'";
        }
        
        if ( !"Exemple + Rdn\u002B ".equals( ava.getValue().getString() ) )
        {
            errors += "\nAva.getUpValue fails '" + ava.getValue().getString() + "'";
        }
        
        if ( !"2.5.4.11=exemple \\+ rdn\\+".equals( ava.normalize() ) )
        {
            errors += "\nAva.normalize fails '" + ava.normalize() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\+\\ ".equals( ava.toString() ) )
        {
            errors += "\nAva.toString fails '" + ava.toString() + "'";
        }
        
        assertEquals( null, errors );
    }
    
    
    @Test
    public void testCompareToSameAva() throws LdapInvalidDnException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "b" );
        Ava atav2 = new Ava( schemaManager, "cn", "b" );
        Ava atav3 = new Ava( schemaManager, "commonName", "b" );
        Ava atav4 = new Ava( schemaManager, "2.5.4.3", "  B  " );

        // 1 with others
        assertEquals( 0, atav1.compareTo( atav1 ) );
        assertEquals( 0, atav1.compareTo( atav2 ) );
        assertEquals( 0, atav1.compareTo( atav3 ) );
        assertEquals( 0, atav1.compareTo( atav4 ) );
        
        // 2 with others
        assertEquals( 0, atav2.compareTo( atav1 ) );
        assertEquals( 0, atav2.compareTo( atav2 ) );
        assertEquals( 0, atav2.compareTo( atav3 ) );
        assertEquals( 0, atav2.compareTo( atav4 ) );
        
        // 3 with others
        assertEquals( 0, atav3.compareTo( atav1 ) );
        assertEquals( 0, atav3.compareTo( atav2 ) );
        assertEquals( 0, atav3.compareTo( atav3 ) );
        assertEquals( 0, atav3.compareTo( atav4 ) );
        
        // 4 with others
        assertEquals( 0, atav4.compareTo( atav1 ) );
        assertEquals( 0, atav4.compareTo( atav2 ) );
        assertEquals( 0, atav4.compareTo( atav3 ) );
        assertEquals( 0, atav4.compareTo( atav4 ) );
    }
    
    
    @Test
    public void testCompareAvaOrder() throws LdapInvalidDnException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "  B  " );
        Ava atav2 = new Ava( schemaManager, "sn", "  c" );
        
        // atav1 should be before atav2
        assertEquals( -1, atav1.compareTo( atav2 ) );
        assertEquals( 1, atav2.compareTo( atav1 ) );

        Ava atav3 = new Ava( schemaManager, "2.5.4.3", "A " );
        
        // Atav1 shoud be after atav3
        assertEquals( 1, atav1.compareTo( atav3 ) );
        assertEquals( -1, atav3.compareTo( atav1 ) );
    }
    
    
    @Test
    public void testSortAva() throws LdapInvalidDnException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "  B  " );
        Ava atav2 = new Ava( schemaManager, "sn", "  c" );
        Ava atav3 = new Ava( schemaManager, "2.5.4.3", "A " );
        Ava atav4 = new Ava( schemaManager, "2.5.4.11", " C  " );
        Ava atav5 = new Ava( schemaManager, "ou", "B " );
        Ava atav6 = new Ava( schemaManager, "ou", "D " );
        Ava atav7 = new Ava( schemaManager, "CN", " " );

        Ava[] avas = new Ava[] { atav1, atav2, atav3, atav4, atav5, atav6, atav7 };
        
        Arrays.sort( avas );
        
        assertEquals( atav5, avas[0] );
        assertEquals( atav4, avas[1] );
        assertEquals( atav6, avas[2] );
        assertEquals( atav7, avas[3] );
        assertEquals( atav3, avas[4] );
        assertEquals( atav1, avas[5] );
        assertEquals( atav2, avas[6] );
    }
}
