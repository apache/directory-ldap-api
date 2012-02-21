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
package org.apache.directory.shared.ldap.model.name;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.SchemaManager;
import org.apache.directory.shared.ldap.schemamanager.impl.DefaultSchemaManager;
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
        assertEquals( "", atav.getUpName() );
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
        assertEquals( "CN=\\ ", ava.getUpName() );

        ava = new Ava( schemaManager, "  CN  ", " " );
        assertEquals( "  CN  =\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "  CN  =\\ ", ava.getUpName() );

        ava = new Ava( schemaManager, "cn", " " );
        assertEquals( "cn=\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "cn=\\ ", ava.getUpName() );

        ava = new Ava( schemaManager, "  cn  ", " " );
        assertEquals( "  cn  =\\ ", ava.toString() );
        assertEquals( "2.5.4.3=\\ ", ava.getNormName() );
        assertEquals( "  cn  =\\ ", ava.getUpName() );
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
        assertEquals( "cn=b", atav.getUpName() );
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
        assertEquals( " CommonName =\\ This is    a TEST\\ ", atav.getUpName() );
    }


    /**
     * Compares two equals atavs
     */
    @Test
    public void testCompareToEquals() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "b" );
        Ava atav2 = new Ava( schemaManager, "cn", "b" );

        assertTrue( atav1.equals( atav2 ) );
    }


    /**
     * Compares two equals atavs but with a type in different case
     */
    @Test
    public void testCompareToEqualsCase() throws LdapException
    {
        Ava atav1 = new Ava( schemaManager, "cn", "b" );
        Ava atav2 = new Ava( schemaManager, "CN", "b" );

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
        
        if ( !"ou=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.getNormName() ) )
        {
            errors = "\nAva.getNormName fails '" + ava.getNormName() + "'";
        }
        
        if ( !"ou".equals( ava.getNormType() ) )
        {
            errors += "\nAva.getNormType fails '" + ava.getNormType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( ava.getNormValue().getString() ) )
        {
            errors += "\nAva.getNormValue fails '" + ava.getNormValue().getString() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.getUpName() ) )
        {
            errors += "\nAva.getUpName fails '" + ava.getUpName() + "'";
        }
        
        if ( !"OU".equals( ava.getUpType() ) )
        {
            errors += "\nAva.getUpType fails '" + ava.getUpType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( ava.getUpValue().getString() ) )
        {
            errors += "\nAva.getUpValue fails '" + ava.getUpValue() .getString() + "'";
        }
        
        if ( !"ou=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.normalize() ) )
        {
            errors += "\nAva.normalize fails '" + ava.normalize() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.toString() ) )
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
        
        Ava ava = new Ava( schemaManager, "OU", "Exemple + Rdn\u00E4 " );
        
        if ( !"2.5.4.11=exemple \\+ rdn\\C3\\A4".equals( ava.getNormName() ) )
        {
            errors = "\nAva.getNormName fails '" + ava.getNormName() + "'";
        }
        
        if ( !"2.5.4.11".equals( ava.getNormType() ) )
        {
            errors += "\nAva.getNormType fails '" + ava.getNormType() + "'";
        }
        
        if ( !"exemple + rdn\u00E4".equals( ava.getNormValue().getString() ) )
        {
            errors += "\nAva.getNormValue fails '" + ava.getNormValue().getString() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.getUpName() ) )
        {
            errors += "\nAva.getUpName fails '" + ava.getUpName() + "'";
        }
        
        if ( !"OU".equals( ava.getUpType() ) )
        {
            errors += "\nAva.getUpType fails '" + ava.getUpType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( ava.getUpValue().getString() ) )
        {
            errors += "\nAva.getUpValue fails '" + ava.getUpValue().getString() + "'";
        }
        
        if ( !"2.5.4.11=exemple \\+ rdn\\C3\\A4".equals( ava.normalize() ) )
        {
            errors += "\nAva.normalize fails '" + ava.normalize() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\\C3\\A4\\ ".equals( ava.toString() ) )
        {
            errors += "\nAva.toString fails '" + ava.toString() + "'";
        }
        
        assertEquals( null, errors );
    }
}
