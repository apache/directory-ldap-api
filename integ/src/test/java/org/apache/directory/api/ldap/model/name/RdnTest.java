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

    
    
    @Test
    public void testRdnValueSchemaAware() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( schemaManager, "cn= TEST\\ " );
        
        if ( !"cn= TEST\\ ".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"2.5.4.3=test\\ ".equals( rdn.getNormName() ) )
        {
            errors = "\nRdn.getNormName fails '" + rdn.getNormName() + "'";
        }
        
        if ( !"test ".equals( rdn.getNormValue( "cn" ) ) )
        {
            errors += "\nRdn.getNormValue( 'cn' ) fails '" + ( String ) rdn.getNormValue( "cn" ) + "'";
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
        
        if ( !"ou=Exemple \\+ Rdn\u00E4\\ +cn=TEST" .equals( rdn.getNormName() ) )
        {
            errors = "\nRdn.getNormName fails '" + rdn.getNormName() + "'";
        }
        
        if ( !"ou".equals( rdn.getNormType() ) )
        {
            errors += "\nRdn.getNormType fails '" + rdn.getNormType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getNormValue() ) )
        {
            errors += "\nRdn.getNormValue fails '" + rdn.getNormValue() + "'";
        }
        
        if ( !"OU".equals( rdn.getType() ) )
        {
            errors += "\nRdn.getUpType fails '" + rdn.getType() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getNormValue() ) )
        {
            errors += "\nRdn.getNormValue fails '" + rdn.getNormValue() + "'";
        }
        
        if ( !"Exemple + Rdn\u00E4 ".equals( rdn.getNormValue( "ou" ) ) )
        {
            errors += "\nRdn.getNormValue( 'ou' ) fails '" + rdn.getNormValue( "ou" ) + "'";
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
        
        if ( !"2.5.4.11=exemple \\+ rdn\u00E4\\ +2.5.4.3=test" .equals( rdn.getNormName() ) )
        {
            errors = "\nRdn.getNormName fails '" + rdn.getNormName() + "'";
        }
        
        if ( !"2.5.4.11".equals( rdn.getNormType() ) )
        {
            errors += "\nRdn.getNormType fails '" + rdn.getNormType() + "'";
        }
        
        if ( !"exemple + rdn\u00E4 ".equals( rdn.getNormValue() ) )
        {
            errors += "\nRdn.getNormValue fails '" + rdn.getNormValue() + "'";
        }
        
        if ( !"OU".equals( rdn.getType() ) )
        {
            errors += "\nRdn.getUpType fails '" + rdn.getType() + "'";
        }
        
        if ( !"Exemple \\+ Rdn\\C3\\A4\\ ".equals( rdn.getValue() ) )
        {
            errors += "\nRdn.getUpValue fails '" + rdn.getValue() + "'";
        }
        
        if ( !"exemple + rdn\u00E4 ".equals( rdn.getNormValue( "ou" ) ) )
        {
            errors += "\nRdn.getNormValue( 'ou' ) fails '" + ( String ) rdn.getNormValue( "ou" ) + "'";
        }
        
        if ( !"test".equals( rdn.getNormValue( "cn" ) ) )
        {
            errors += "\nRdn.getNormValue( 'cn' ) fails '" + ( String ) rdn.getNormValue( "cn" ) + "'";
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
        assertEquals( rdn1.getNormName(), rdn2.getNormName() );
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
        
        //assertEquals( rdn1, rdn2 );
    }

    
    @Test
    public void testRdnEscapedValue() throws Exception
    {
         new Rdn( schemaManager, "sn=\\46\\65\\72\\72\\79" );
    }
}
