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

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;

/**
 * Tests for the schemaAware Rdn class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class RdnTest
{
    private static SchemaManager schemaManager;


    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }



    /**
     * Test a null Rdn
     */
    @Test
    public void testRdnNull()
    {
        Rdn rdn = new Rdn( schemaManager );
        assertEquals( "", rdn.toString() );
        assertEquals( "", rdn.getName() );
        assertEquals( "", rdn.getNormName() );
    }


    /**
     * test an empty Rdn
     * 
     * @throws LdapException
     */
    @Test
    public void testRdnEmpty() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, "" );
        assertEquals( "", rdn.toString() );
        assertEquals( "", rdn.getName() );
        assertEquals( "", rdn.getNormName() );
    }


    /**
     * test a simple Rdn : ' cn = b    C d'
     * 
     * @throws LdapException
     */
    @Test
    public void testRdnSimple() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " cn = b    C d" );
        assertEquals( " cn = b    C d", rdn.toString() );
        assertEquals( " cn = b    C d", rdn.getName() );
        assertEquals( "2.5.4.3= b  c  d ", rdn.getNormName() );

        Rdn rdn2 = new Rdn( " cn = b    C d" );
        assertEquals( " cn = b    C d", rdn2.toString() );
        assertEquals( " cn = b    C d", rdn2.getName() );
        assertEquals( "cn=b    C d", rdn2.getNormName() );
    }


    /**
     * test a simple Rdn with no value : ' dc = '
     * 
     * @throws LdapException
     */
    @Test
    public void testRdnSimpleEmptyValue() throws LdapException
    {
        Rdn rdn = new Rdn( schemaManager, " dc = " );
        assertEquals( " dc = ", rdn.toString() );
        assertEquals( " dc = ", rdn.getName() );
        assertEquals( "0.9.2342.19200300.100.1.25=  ", rdn.getNormName() );
    }
    
    
    @Test
    public void testRdnValueSchemaAware() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( schemaManager, "cn= TEST\\ " );
        
        if ( !"cn= TEST\\ ".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"cn=TEST\\ ".equals( rdn.getEscaped() ) )
        {
            errors = "\nRdn.getEscaped fails '" + rdn.getEscaped() + "'";
        }
        
        if ( !"TEST ".equals( rdn.getValue( "cn" ) ) )
        {
            errors += "\nRdn.getEscaped( 'cn' ) fails '" + ( String ) rdn.getValue( "cn" ) + "'";
        }
        
        assertEquals( null, errors );
    }

    
    @Test
    public void testRdnValuesNoSchema() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( "OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST" );
        
        if ( !"OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\u00E4\\ +cn=TEST" .equals( rdn.getEscaped() ) )
        {
            errors = "\nRdn.getEscaped fails '" + rdn.getEscaped() + "'";
        }
        
        if ( !"ou".equals( rdn.getNormType() ) )
        {
            errors += "\nRdn.getNormType fails '" + rdn.getNormType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getValue() ) )
        {
            errors += "\nRdn.getEscaped fails '" + rdn.getValue() + "'";
        }
        
        if ( !"OU".equals( rdn.getType() ) )
        {
            errors += "\nRdn.getUpType fails '" + rdn.getType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getValue( "ou" ) ) )
        {
            errors += "\nRdn.getEscaped( 'ou' ) fails '" + rdn.getValue( "ou" ) + "'";
        }
        
        if ( !"TEST".equals( rdn.getValue( "cn" ) ) )
        {
            errors += "\nRdn.getValue( 'test' ) fails '" + rdn.getValue( "cn" ) + "'";
        }
        
        if ( !"OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST".equals( rdn.toString() ) )
        {
            errors += "\nRdn.toString fails '" + rdn.toString() + "'";
        }
        
        assertEquals( null, errors );
    }
    
    
    @Test
    public void testRdnValuesSchemaAware() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( schemaManager, "OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST" );
        
        if ( !"OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\u00E4\\ +cn=TEST" .equals( rdn.getEscaped() ) )
        {
            errors = "\nRdn.getEscaped fails '" + rdn.getEscaped() + "'";
        }
        
        if ( !"2.5.4.11".equals( rdn.getNormType() ) )
        {
            errors += "\nRdn.getNormType fails '" + rdn.getNormType() + "'";
        }
        
        if ( !"OU=Exemple \\+ Rdn\u00E4\\ +cn=TEST".equals( rdn.getEscaped() ) )
        {
            errors += "\nRdn.getEscaped fails '" + rdn.getEscaped() + "'";
        }
        
        if ( !"OU".equals( rdn.getType() ) )
        {
            errors += "\nRdn.getUpType fails '" + rdn.getType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getValue() ) )
        {
            errors += "\nRdn.getUpValue fails '" + rdn.getValue() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getValue( "ou" ) ) )
        {
            errors += "\nRdn.getValue( 'ou' ) fails '" + ( String ) rdn.getValue( "ou" ) + "'";
        }
        
        if ( !"TEST".equals( rdn.getValue( "cn" ) ) )
        {
            errors += "\nRdn.getEscaped( 'cn' ) fails '" + ( String ) rdn.getValue( "cn" ) + "'";
        }
        
        if ( !"OU = Exemple \\+ Rdn\\C3\\A4\\ +cn= TEST".equals( rdn.toString() ) )
        {
            errors += "\nRdn.toString fails '" + rdn.toString() + "'";
        }
        
        assertEquals( null, errors );
    }
    
    
    @Test
    public void testRdnMultipleAvas() throws Exception
    {
        Rdn rdn1 = new Rdn( schemaManager, "cn=doe+gn=john" );
        Rdn rdn2 = new Rdn( schemaManager, "gn=john+cn=doe" );
        
        assertEquals( rdn1, rdn2 );
    }
    
    
    /**
     * test that a RDN with an attributeType used twice with the same value
     * throws an exception
     */
    @Test( expected=LdapInvalidDnException.class )
    public void testWrongRdnAtUsedTwiceSameValue() throws LdapException
    {
        new Rdn( schemaManager, " cn = b + cn = b " );
    }
    
    
    /**
     * test that a RDN with an attributeType used twice but with different value
     * is accepted
     */
    @Test
    public void testRdnAtUsedTwiceDifferentValue() throws LdapException
    {
        Rdn rdn1 = new Rdn( schemaManager, " cn = c + cn = b " );
        Rdn rdn2 = new Rdn( schemaManager, " cn = b + cn = c " );
        
        assertEquals( rdn1, rdn2 );
    }

    
    @Test
    public void testRdnEscapedValue() throws Exception
    {
         new Rdn( schemaManager, "sn=\\46\\65\\72\\72\\79" );
    }
}
