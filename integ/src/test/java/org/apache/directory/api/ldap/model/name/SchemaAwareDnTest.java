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
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the class Dn
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SchemaAwareDnTest
{
    private static SchemaManager schemaManager;


    /**
     * Initialize OIDs maps for normalization
     * 
     * @throws Exception If the setup failed
     */
    @BeforeAll
    public static void setup() throws Exception
    {
        schemaManager = new DefaultSchemaManager();
    }

    /**
     * test a simple Dn with multiple NameComponents : cn=Kate + sn=Bush,ou=system
     * 
     * @throws LdapException If the test failed
     */
    @Test
    @Disabled
    public void testDnSimpleMultivaluedAttribute() throws LdapException
    {
        Dn dn = new Dn( schemaManager, "cn=Kate+sn=Bush,ou=system" );

        assertTrue( Dn.isValid( "cn=Kate+sn=Bush,ou=system" ) );
        assertEquals( "2.5.4.3= kate +2.5.4.4= bush ,2.5.4.11= system ", dn.getNormName() );

        Dn dn2 = new Dn( schemaManager, "sn=Bush+cn=Kate,ou=system" );

        assertTrue( Dn.isValid( "sn=Bush+cn=Kate,ou=system" ) );
        assertEquals( "2.5.4.3= kate +2.5.4.4= bush ,2.5.4.11= system ", dn2.getNormName() );
        
        assertEquals( dn, dn2 );
    }
}
