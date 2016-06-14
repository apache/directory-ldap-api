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
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;

import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;

/**
 * Tests for the schemaAware Rdn class when using teh FastParser
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class FastParserRdnTest
{
    private static SchemaManager schemaManager;


    @BeforeClass
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }
    
    
    @Test
    public void testSimpleRdnValueSchemaAware() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( schemaManager, "CommonName = TEST " );
        
        if ( !"CommonName = TEST ".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"2.5.4.3=test".equals( rdn.getNormName() ) )
        {
            errors = "\nRdn.getNormName fails '" + rdn.getNormName() + "'";
        }
        
        if ( !"test".equals( rdn.getNormValue( "cn" ) ) )
        {
            errors += "\nRdn.getNormValue( 'cn' ) fails '" + ( String ) rdn.getNormValue( "cn" ) + "'";
        }
        
        assertEquals( null, errors );
    }
    
    
    @Test
    public void testSimpleRdnValueNullSchemaManager() throws LdapException
    {
        String errors = null;
        
        Rdn rdn = new Rdn( (SchemaManager)null, "Cn= TEST " );
        
        if ( !"Cn= TEST ".equals( rdn.getName() ) )
        {
            errors += "\nRdn.getName fails '" + rdn.getName() + "'";
        }
        
        if ( !"cn=TEST".equals( rdn.getNormName() ) )
        {
            errors = "\nRdn.getNormName fails '" + rdn.getNormName() + "'";
        }
        
        if ( !"TEST".equals( rdn.getNormValue( "cn" ) ) )
        {
            errors += "\nRdn.getNormValue( 'cn' ) fails '" + ( String ) rdn.getNormValue( "cn" ) + "'";
        }
        
        assertEquals( null, errors );
    }
}
