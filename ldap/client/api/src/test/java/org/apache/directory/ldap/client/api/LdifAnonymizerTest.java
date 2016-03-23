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


import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.Strings;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertNotSame;


/**
 * A class used to test the LDIFAnonymizer
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifAnonymizerTest
{
    private SchemaManager schemaManager;
    
    private LdifReader ldifReader;

    
    @Before
    public void setup()
    {
        schemaManager = null;
        
        try
        {
            schemaManager = new DefaultSchemaManager();
            ldifReader = new LdifReader( schemaManager );
        }
        catch ( Exception e )
        {
            // Todo : we need a schemaManager
            System.out.println( "Missing a SchemaManager !" );
            System.exit( -1 );
        }
    }
    
    
    @Test
    public void testLdifAnonymizer() throws Exception
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
            "sn: lecharnye\n"+
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
        
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 3, entries.size() );
        
        // First entry
        LdifEntry ldifEntry = entries.get( 0 );
        assertTrue( ldifEntry.isEntry() );
        
        Entry entry = ldifEntry.getEntry();
        assertEquals( 3, entry.size() );
        
        assertEquals( "cn=AAAA,dc=example,dc=com", entry.getDn().toString() );

        Attribute cn = entry.get( "cn" );
        assertEquals( "AAAA", cn.getString() );

        Attribute sn = entry.get( "sn" );
        assertEquals( "AAAA", sn.getString() );
        
        // Second entry
        ldifEntry = entries.get( 1 );
        assertTrue( ldifEntry.isEntry() );
        
        entry = ldifEntry.getEntry();
        assertEquals( 3, entry.size() );
        
        assertEquals( "cn=AAAAAAAA,dc=acme,dc=com", entry.getDn().toString() );

        cn = entry.get( "cn" );
        assertEquals( "AAAAAAAA", cn.getString() );

        sn = entry.get( "sn" );
        assertEquals( "AAAAAAAAA", sn.getString() );
        
        // Third entry
        ldifEntry = entries.get( 2 );
        assertTrue( ldifEntry.isEntry() );
        
        entry = ldifEntry.getEntry();
        assertEquals( 4, entry.size() );
        
        assertEquals( "cn=AAAAAAAA,dc=AAAA,dc=example,dc=com", entry.getDn().toString() );

        cn = entry.get( "cn" );
        assertEquals( "AAAAAAAA", cn.getString() );

        sn = entry.get( "sn" );
        assertEquals( "AAAAAAAAB", sn.getString() );

        Attribute seeAlso = entry.get( "seeAlso" );
        assertEquals( "cn=AAAAAAAA,dc=acme,dc=com", seeAlso.getString() );
    }


    @Test
    public void testLdifAnonymizer2() throws Exception
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
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 1, entries.size() );
        
        // Check the entry
        LdifEntry ldifEntry = entries.get( 0 );
        assertTrue( ldifEntry.isEntry() );
        
        Entry entry = ldifEntry.getEntry();
        assertEquals( 4, entry.size() );
        
        // Here, we expect cn2 to be translated to AAA, because it was encountered in teh DN first
        assertEquals( "cn=AAA+sn=AAAAAAAAA,dc=example,dc=com", entry.getDn().toString() );

        Attribute cn = entry.get( "cn" );
        assertEquals( 3, cn.size() );
        assertTrue( cn.contains( "AAA", "AAB", "AAC" ) );

        Attribute sn = entry.get( "sn" );
        assertEquals( "AAAAAAAAA", sn.getString() );

        Attribute givenname = entry.get( "givenname" );
        assertEquals( "AAAA", givenname.getString() );
    }


    @Test
    public void testLdifAnonymizer3() throws Exception
    {
        String ldif =
            "dn: cn=cn2 + sn=elecharny, dc=example, dc=com\n" +
                "ObjectClass: top\n" +
                "objectClass: person\n" +
                "cn: cn1\n" +
                "cn: cn2\n" +
                "cn: cn3\n" +
                "userPassword: test\n" +
                "userPassword: tesu\n" +
                "sn: elecharny\n" +
                "givenname: test\n";

        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "dc=example,dc=com" );
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 1, entries.size() );
        
        // Check the entry
        LdifEntry ldifEntry = entries.get( 0 );
        assertTrue( ldifEntry.isEntry() );
        
        Entry entry = ldifEntry.getEntry();
        assertEquals( 5, entry.size() );
        
        // Here, we expect cn2 to be translated to AAA, because it was encountered in teh DN first
        assertEquals( "cn=AAA+sn=AAAAAAAAA,dc=example,dc=com", entry.getDn().toString() );

        Attribute cn = entry.get( "cn" );
        assertEquals( 3, cn.size() );
        assertTrue( cn.contains( "AAA", "AAB", "AAC" ) );

        Attribute sn = entry.get( "sn" );
        assertEquals( "AAAAAAAAA", sn.getString() );

        Attribute givenname = entry.get( "givenname" );
        assertEquals( "AAAA", givenname.getString() );

        Attribute userPassword = entry.get( "userPassword" );
        assertEquals( 2, userPassword.size() );
        assertTrue( userPassword.contains( Strings.getBytesUtf8( "AAAA" ) ) );
        assertTrue( userPassword.contains( Strings.getBytesUtf8( "AAAB" ) ) );
    }


    @Test
    public void testLdifAnonymizerChangeType() throws Exception
    {
        String ldif =
            "dn: cn=test,ou=Groups,o=acme,dc=com\n" +
            "changetype: modify\n" +
            "replace: member\n" +
            "member::Y249YWNtZTEuY29tLG91PVNlcnZlcnMsbz1hY21lLGRjPWNvbQ==\n" +                  // cn=acme1.com,ou=Servers,o=acme,dc=com
            "member::dWlkPWpvaG4uZG9lQGFjbWUuY29tLG91PVBlb3BsZSxvPWFjbWUsZGM9Y29t\n" +          // uid=john.doe@acme.com,ou=People,o=acme,dc=com
            "member::dWlkPWphY2suZG9lQGFjbWUuY29tLG91PVBlb3BsZSxvPWFjbWUsZGM9Y29t\n" +          // uid=jack.doe@acme.com,ou=People,o=acme,dc=com
            "member::dWlkPWppbS5nb256YWxlc0BhY21lLmNvbSxvdT1QZW9wbGUsbz1hY21lLGRjPWNvbQ==\n" +  // uid=jim.gonzales@acme.com,ou=People,o=acme,dc=com
            "-";
        
        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "o=acme,dc=com" );
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 1, entries.size() );
        
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isChangeModify() );
        assertEquals( 1, entry.getModifications().size() );
        
        Modification modification = entry.getModifications().get( 0 );
        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modification.getOperation() );

        Attribute attribute = modification.getAttribute();
        assertEquals( "member", attribute.getUpId() );
        assertEquals( 4, attribute.size() );
        
        Set<String> values = new HashSet<String>();
        values.add( "cn=AAAAAAAAA,ou=AAAAAAA,o=acme,dc=com" );
        values.add( "uid=AAAAAAAAAAAAAAAAA,ou=AAAAAB,o=acme,dc=com" );
        values.add( "uid=AAAAAAAAAAAAAAAAB,ou=AAAAAB,o=acme,dc=com" );
        values.add( "uid=AAAAAAAAAAAAAAAAAAAAA,ou=AAAAAB,o=acme,dc=com" );
        
        for ( Value<?> value : attribute )
        {
            String str = value.getString();
            
            // We can only test the length and teh fact teh values are not equal (as the vale has been anonymized)
            assertTrue( values.contains( str ) );
            assertTrue( str.endsWith( ",o=acme,dc=com" ) );
        }
    }
    
    
    @Test
    public void testAnonymizeModify() throws Exception
    {
        String ldif = 
            "dn: mail=legal@acme.com,ou=Email,ou=Services,o=acme,dc=com\n" +
            "changetype: modify\n" +
            "replace: cn\n" +
            "cn::QUNNRSBJbmMuIExlZ2FsIFRlYW0=\n" +
            "-";
        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "o=acm,dc=com" );
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 1, entries.size() );
        
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isChangeModify() );
        assertEquals( 1, entry.getModifications().size() );
        
        Modification modification = entry.getModifications().get( 0 );
        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modification.getOperation() );

        Attribute attribute = modification.getAttribute();
        assertEquals( "cn", attribute.getUpId() );
        assertEquals( 1, attribute.size() );
        
        String value = attribute.getString();
        
        // We can only test the length and the fact the values are not equal (as the vale has been anonymized)
        assertEquals( "AAAAAAAAAAAAAAAAAAAA".length(), value.length() );
        assertEquals( "AAAAAAAAAAAAAAAAAAAA", value );
    }
    
    
    @Test
    public void testAnonymizeModifyAddDeleteUnknownAttribute() throws Exception
    {
        String ldif = 
            "dn: uid=jdoe@acme.com,ou=People,o=acme.com\n" +
            "changetype: modify\n" +
            "delete: acmeAttr\n" +
            "acmeAttr::dWlkPWpvaG4uZG9lQGFjbWUuY29tLG91PXBlb3BsZSxvPWFjbWUuY29t\n" +
            "-\n" +
            "add: acmeAttr\n" +
            "acmeAttr::dWlkPWpvaG4uZG9lQGFjbWVOZXcuY29tLG91PXBlb3BsZSxvPWFjbWUuY29t\n" +
            "-";
        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "o=acme.com" );
        String result = anonymizer.anonymize( ldif );
        
        assertEquals( "", result );
    }
    
    
    @Test
    public void testAnonymizerModifyBinaryOptionAttribute() throws LdapException, IOException
    {
        String ldif = 
            "dn: cn=Acme certificate,o=Acme,c=US,ou=IT Infrastructure,o=acme.com\n" +
            "changetype: modify\n" +
            "replace: certificateRevocationList;binary\n" +
            "certificateRevocationList;binary::YmxhaCBibGFo\n" +
            "-";

        LdifAnonymizer anonymizer = new LdifAnonymizer( schemaManager );
        anonymizer.addNamingContext( "o=acme.com" );
        String result = anonymizer.anonymize( ldif );
        
        List<LdifEntry> entries = ldifReader.parseLdif( result );
        
        assertEquals( 1, entries.size() );
        
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isChangeModify() );
        assertEquals( 1, entry.getModifications().size() );
        
        Modification modification = entry.getModifications().get( 0 );
        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, modification.getOperation() );

        Attribute attribute = modification.getAttribute();
        assertEquals( "certificateRevocationList;binary", attribute.getUpId() );
        assertEquals( 1, attribute.size() );
        
        for ( Value<?> value : attribute )
        {
            String str = value.getString();
            
            // We can only test the length and the fact the values are not equal (as the vale has been anonymized)
            assertNotSame( 0, value.length() );
            assertEquals( str.length(), value.length() );
        }
    }
}
