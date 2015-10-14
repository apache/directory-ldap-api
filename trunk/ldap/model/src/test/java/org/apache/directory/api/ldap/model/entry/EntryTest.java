/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.entry;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.Test;


/**
 * Test the Entry class
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EntryTest
{
    @Test
    public void testEntryCreation() throws LdapException
    {
        Entry entry = new DefaultEntry();

        entry.setDn( "dc=example, dc=com" );
        entry.add( "objectClass", "top", "domain" );
        entry.add( "dc", "example" );

        assertNotNull( entry.getDn() );
        assertEquals( new Dn( "dc=example, dc=com" ), entry.getDn() );
        assertNotNull( entry.getAttributes() );
        assertEquals( 2, entry.size() );
        assertTrue( entry.contains( "objectClass", "top", "domain" ) );
        assertTrue( entry.contains( "dc", "example" ) );
        assertFalse( entry.isSchemaAware() );

        Entry entry2 = new DefaultEntry( "dc=example, dc=com" );
        entry2.add( "objectClass", "top", "domain" );
        entry2.add( "dc", "example" );

        assertEquals( entry, entry2 );
    }
}
