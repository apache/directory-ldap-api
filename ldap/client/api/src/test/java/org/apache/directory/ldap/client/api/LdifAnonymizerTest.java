/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.ldap.client.api;


import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.junit.BeforeClass;
import org.junit.Test;


/**
 * A class used to test the LDIFAnonymizer
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifAnonymizerTest
{
    private static SchemaManager schemaManager;
    
    @BeforeClass
    public static void setup()
    {
        schemaManager = null;
        
        try
        {
            schemaManager = new DefaultSchemaManager();
        }
        catch ( Exception e )
        {
            // Todo : we need a schemaManager
            System.out.println( "Missing a SchemaManager !" );
            System.exit( -1 );
        }
    }
    
    
    @Test
    public void testLdifAnonymizer() throws Exception, Exception
    {
        String ldif =
            "dn: cn=test,dc=example,dc=com\n" +
            "ObjectClass: top\n" +
            "objectClass: person\n" +
            "cn: test\n" +
            "sn: Test\n" +
            "\n" +
            "dn: cn=emmanuel,dc=acme,dc=com\n" +
            "ObjectClass: top\n" +
            "objectClass: person\n" +
            "cn: emmanuel\n" +
            "sn: elecharny\n"+
            "\n" +
            "dn: cn=emmanuel,dc=test,dc=example,dc=com\n" +
            "ObjectClass: top\n" +
            "objectClass: person\n" +
            "cn: emmanuel\n" +
            "seeAlso: cn=emmanuel,dc=acme,dc=com\n" +
            "sn: elecharny\n";

        SchemaManager schemaManager = null;
        
        try
        {
            schemaManager = new DefaultSchemaManager();
        }
        catch ( Exception e )
        {
            // Todo : we need a schemaManager
            System.out.println( "Missing a SchemaManager !" );
            System.exit( -1 );
        }

        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "dc=example,dc=com" );
        anonymizer.addNamingContext( "dc=acme,dc=com" );
        anonymizer.removeAnonAttributeType( schemaManager.getAttributeType( "sn" ) );
        
        anonymizer.anonymize( ldif );
    }


    @Test
    public void testLdifAnonymizer2() throws Exception, Exception
    {
        String ldif =
            "dn: cn=cn2 + sn=elecharny, dc=example, dc=com\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn: cn1\n" +
                "cn: cn2\n" +
                "cn: cn3\n" +
                "sn: elecharny\n" +
                "givenname: test\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "dc=example,dc=com" );
        anonymizer.anonymize( ldif );
    }


    @Test
    public void testLdifAnonymizer3() throws Exception, Exception
    {
        String ldif =
            "dn: cn=cn2 + sn=elecharny, dc=example, dc=com\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn: cn1\n" +
                "cn: cn2\n" +
                "cn: cn3\n" +
                "userPassword: test\n" +
                "sn: elecharny\n" +
                "givenname: test\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "dc=example,dc=com" );
        anonymizer.anonymize( ldif );
    }


    @Test
    public void testLdifAnonymizer4() throws Exception, Exception
    {
        String ldif =
            "dn: ou=PD Accountants, ou=Product Development, ou=usa, dc=airius, dc=com\n" +
            "changetype: modrdn\n" +
            "newrdn: ou=Product Development Accountants\n" +
            "deleteoldrdn: 0\n" +
            "newsuperior: ou=Accounting, ou=usa, dc=airius, dc=com\n" +
            "\n" +
            "dn: cn=Paula Jensen, ou=Product Development, dc=airius, dc=com\n" +
            "changetype: modify\n" +
            "add: postaladdress\n" +
            "postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086\n" +
            "-\n" +
            "delete: description\n" +
            "-\n" +
            "replace: telephonenumber\n" +
            "telephonenumber: +1 408 555 1234\n" +
            "telephonenumber: +1 408 555 5678\n" +
            "-\n" +
            "delete: facsimiletelephonenumber\n" +
            "facsimiletelephonenumber: +1 408 555 9876\n" +
            "-\n" +
            "\n" +
            "dn: cn=cn2,ou=People,o=hp.com\n" +
            "changetype: add\n" +
            "ObjectClass: top\n" +
            "objectClass: person\n" +
            "cn: cn1\n" +
            "cn: cn2\n" +
            "cn: cn3\n" +
            "userPassword: test\n" +
            "sn: elecharny\n" +
            "givenname: test\n" +
            "\n" +
            "dn: uid=thayapari.a.wijesundara@hp.com,ou=People,o=hp.com\n" +
            "changetype: delete\n" +
            "\n" +
            "dn: uid=thayapari.a.wijesundara@hp.com,ou=People,o=hp.com\n" +
            "changetype: modify\n" +
            "replace: telephoneNumber\n" +
            "telephoneNumber::KzYxIDIgODI3ODQ2NDQ=\n" +
            "-\n" +
            "\n" +
            "dn: uid=thayapari.a.wijesundara@hp.com,ou=People,o=hp.com\n" +
            "changetype: modify\n" +
            "replace: telephoneNumber\n" +
            "telephoneNumber::KzYxIDIgODI3ODQ2NDQ=\n" +
            "-\n" +
            "\n" +
            "dn: cn=vsmuser_g1u2283c,ou=Groups,o=hp.com\n" +
            "changetype: modify\n" +
            "replace: member\n" +
            "member::Y249dnNtLmhvdXN0b24uaHAuY29tLG91PVNlcnZlcnMsbz1ocC5jb20=\n" +
            "member::dWlkPXRpbS50dXNzaW5nQGhwLmNvbSxvdT1QZW9wbGUsbz1ocC5jb20=\n" +
            "member::dWlkPXRpbS50dXNzaW5nQGhwZS5jb20sb3U9UGVvcGxlLG89aHAuY29t\n" +
            "member::dWlkPW1hcnRoYWxhLm5pci5yZWRkeUBocGUuY29tLG91PVBlb3BsZSxvPWhwLmNvbQ==\n" +
            "-";
        
        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "dc=example,dc=com" );
        anonymizer.anonymize( ldif );
    }
}
