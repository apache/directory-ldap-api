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
package org.apache.directory.api.ldap.ldif;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.apache.directory.api.ldap.model.ldif.LdapLdifException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that a schema-aware LdifReader does not silently drop attributes that
 * fail schema validation : with a strict SchemaManager, a record containing an
 * attribute the schema rejects must fail the parse instead of being reported
 * as successfully parsed with the attribute missing.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class LdifReaderStrictSchemaRejectTest
{
    /**
     * With a strict SchemaManager, an unknown attribute must fail the parse
     * visibly : the record must not be returned without the attribute.
     */
    @Test
    public void testStrictSchemaManagerUnknownAttributeFailsParse() throws Exception
    {
        SchemaManager schemaManager = new DefaultSchemaManager();

        String ldif =
            "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n"
                + "cn: app1\n"
                + "objectClass: top\n"
                + "objectClass: apApplication\n"
                + "unknownAttribute: some value\n";

        try ( LdifReader reader = new LdifReader( schemaManager ) )
        {
            assertThrows( LdapLdifException.class, () -> reader.parseLdif( ldif ) );
        }
    }


    /**
     * With a relaxed SchemaManager, the recovery path still applies : the
     * unknown attribute is kept in the entry via a generated AttributeType.
     */
    @Test
    public void testRelaxedSchemaManagerUnknownAttributeIsKept() throws Exception
    {
        SchemaManager schemaManager = new DefaultSchemaManager();
        schemaManager.setRelaxed();

        String ldif =
            "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n"
                + "cn: app1\n"
                + "objectClass: top\n"
                + "objectClass: apApplication\n"
                + "unknownAttribute: some value\n";

        try ( LdifReader reader = new LdifReader( schemaManager ) )
        {
            List<LdifEntry> entries = reader.parseLdif( ldif );

            assertEquals( 1, entries.size() );
            assertNotNull( entries.get( 0 ).get( "unknownAttribute" ) );
        }
    }
}
