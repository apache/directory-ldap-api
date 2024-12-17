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
package org.apache.directory.api.ldap.model.ldif;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the LdifReader class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdifReaderTest
{
    private static byte[] data;

    private static File HJENSEN_JPEG_FILE = null;
    private static File FIONA_JPEG_FILE = null;


    private static File createFile( String name, byte[] data ) throws IOException
    {
        File jpeg = File.createTempFile( name, "jpg" );

        jpeg.createNewFile();

        DataOutputStream os = new DataOutputStream( new FileOutputStream( jpeg ) );

        os.write( data );
        os.close();

        // This file will be deleted when the JVM
        // will exit.
        jpeg.deleteOnExit();

        return jpeg;
    }


    /**
     * Create a file to be used by ":@lt;" values
     * 
     * @throws Exception If the setup failed
     */
    @BeforeAll
    public static void setUp() throws Exception
    {
        data = new byte[256];

        for ( int i = 0; i < 256; i++ )
        {
            data[i] = ( byte ) i;
        }

        HJENSEN_JPEG_FILE = createFile( "hjensen", data );
        FIONA_JPEG_FILE = createFile( "fiona", data );
    }


    @Test
    public void testLdifNull() throws Exception
    {
        String ldif = null;

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
    }


    @Test
    public void testLdifEmpty() throws Exception
    {
        String ldif = "";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
    }


    @Test
    public void testLdifEmptyLines() throws Exception
    {
        String ldif = "\n\n\r\r\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
    }


    @Test
    public void testLdifComments() throws Exception
    {
        String ldif =
            "#Comment 1\r" +
                "#\r" +
                " th\n" +
                " is is still a comment\n" +
                "\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
    }


    @Test
    public void testLdifVersion() throws Exception
    {
        String ldif =
            "#Comment 1\r" +
                "#\r" +
                " th\n" +
                " is is still a comment\n" +
                "\n" +
                "version:\n" +
                " 1\n" +
                "# end";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
        assertEquals( 1, reader.getVersion() );
    }


    @Test
    public void testLdifVersionStart() throws Exception
    {
        String ldif =
            "version:\n" +
                " 1\n" +
                "\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, reader.getVersion() );
        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );

        assertTrue( entry.isLdifContent() );

        assertEquals( ldif.length(), entry.getLengthBeforeParsing() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );
    }


    /**
     * Test the ldif parser with a file without a version. It should default to 1
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifWithoutVersion() throws Exception
    {
        String ldif =
            "#Comment 1\r" +
                "#\r" +
                " th\n" +
                " is is still a comment\n" +
                "\n" +
                "# end";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 0, entries.size() );
        assertEquals( 1, reader.getVersion() );
    }


    /**
     * Spaces at the end of values should not be included into values.
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserEndSpaces() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();

        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );

        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

    }


    @Test
    public void testEntryReaderPreservesAttributeCase() throws Exception
    {
        // content record
        String ldif = "version:   1\n" +
            "dn: dc=example,dc=com\n" +
            "objectClass: top\n";

        testEntryReaderPreservesAttributeCase( ldif );

        // changetype add
        ldif = "version:   1\n" +
            "dn: dc=example,dc=com\n" +
            "changetype: add\n" +
            "objectClass: top\n";

        testEntryReaderPreservesAttributeCase( ldif );
    }


    private void testEntryReaderPreservesAttributeCase( String ldif ) throws Exception
    {
        LdifReader reader = new LdifReader();

        List<LdifEntry> entries = reader.parseLdif( ldif );
        assertNotNull( entries );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertEquals( 1, entry.getEntry().size() );
        Attribute attr = entry.getEntry().get( "objectClass" );
        assertEquals( "objectclass", attr.getId() );
        assertEquals( "objectClass", attr.getUpId() );
    }


    @Test
    public void testLdifParserAddAttrCaseInsensitiveAttrId() throws Exception
    {
        // test that mixed case attr ids work at all
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: modify\n" +
                "add: administrativeRole\n" +
                "administrativeRole: accessControlSpecificArea\n" +
                "-";

        testReaderAttrIdCaseInsensitive( ldif );

        // test that attr id comparisons are case insensitive and that the version in the add: line is used.
        // See DIRSERVER-1029 for some discussion.
        ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: modify\n" +
                "add: administrativeRole\n" +
                "administrativerole: accessControlSpecificArea\n" +
                "-";

        testReaderAttrIdCaseInsensitive( ldif );
    }


    private void testReaderAttrIdCaseInsensitive( String ldif ) throws Exception
    {
        LdifReader reader = new LdifReader();

        List<LdifEntry> entries = reader.parseLdif( ldif );
        assertNotNull( entries );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertTrue( entry.isChangeModify() );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        List<Modification> mods = entry.getModifications();
        assertTrue( mods.size() == 1 );
        Attribute attr = mods.get( 0 ).getAttribute();
        assertTrue( attr.getId().equals( "administrativerole" ) );
        assertEquals( attr.getString(), "accessControlSpecificArea" );
    }


    /**
     * Changes and entries should not be mixed
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserCombinedEntriesChanges() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:\n" +
                "\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113556.1.4.805 true\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    /**
     * Changes and entries should not be mixed
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserCombinedEntriesChanges2() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:\n" +
                "\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    /**
     * Changes and entries should not be mixed
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserCombinedChangesEntries() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113556.1.4.805 true\n" +
                "changetype: delete\n" +
                "\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    /**
     * Changes and entries should not be mixed
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserCombinedChangesEntries2() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "changetype: delete\n" +
                "\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    @Test
    public void testLdifParser() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1   \n" +
                "dependencies:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "cn" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "apApplication" ) );

        attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "dependencies" );
        assertEquals( "", attr.get().getString() );

        attr = entry.get( "envvars" );
        assertEquals( "", attr.get().getString() );
    }


    @Test
    public void testLdifParserMuiltiLineComments() throws Exception
    {
        String ldif =
            "#comment\n" +
                " still a comment\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1#another comment\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1\n" +
                "serviceType: http\n" +
                "dependencies:\n" +
                "httpHeaders:\n" +
                "startupOptions:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "cn" );
        assertTrue( attr.contains( "app1#another comment" ) );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "apApplication" ) );

        attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "dependencies" );
        assertEquals( "", attr.get().getString() );

        attr = entry.get( "envvars" );
        assertEquals( "", attr.get().getString() );
    }


    @Test
    public void testLdifParserMultiLineEntries() throws Exception
    {
        String ldif =
            "#comment\n" +
                "dn: cn=app1,ou=appli\n" +
                " cations,ou=conf,dc=apache,dc=org\n" +
                "cn: app1#another comment\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1\n" +
                "serviceType: http\n" +
                "dependencies:\n" +
                "httpHeaders:\n" +
                "startupOptions:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "cn" );
        assertTrue( attr.contains( "app1#another comment" ) );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "apApplication" ) );

        attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "dependencies" );
        assertEquals( "", attr.get().getString() );

        attr = entry.get( "envvars" );
        assertEquals( "", attr.get().getString() );
    }


    @Test
    public void testLdifParserBase64() throws Exception
    {
        String ldif =
            "#comment\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn:: RW1tYW51ZWwgTMOpY2hhcm55\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1\n" +
                "serviceType: http\n" +
                "dependencies:\n" +
                "httpHeaders:\n" +
                "startupOptions:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "cn" );
        assertTrue( attr.contains( "Emmanuel L\u00e9charny".getBytes( StandardCharsets.UTF_8 ) ) );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "apApplication" ) );

        attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "dependencies" );
        assertEquals( "", attr.get().getString() );

        attr = entry.get( "envvars" );
        assertEquals( "", attr.get().getString() );
    }


    @Test
    public void testLdifParserBase64MultiLine() throws Exception
    {
        String ldif =
            "#comment\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn:: RW1tYW51ZWwg\n" +
                " TMOpY2hhcm55ICA=\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1\n" +
                "serviceType: http\n" +
                "dependencies:\n" +
                "httpHeaders:\n" +
                "startupOptions:\n" +
                "envVars:";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=app1,ou=applications,ou=conf,dc=apache,dc=org", entry.getDn().getName() );

        Attribute attr = entry.get( "cn" );
        assertTrue( attr.contains( "Emmanuel L\u00e9charny  ".getBytes( StandardCharsets.UTF_8 ) ) );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "apApplication" ) );

        attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );

        attr = entry.get( "dependencies" );
        assertEquals( "", attr.get().getString() );

        attr = entry.get( "envvars" );
        assertEquals( "", attr.get().getString() );
    }


    @Test
    public void testLdifParserRFC2849Sample1() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Barbara Jensen\n" +
                "cn: Barbara J Jensen\n" +
                "cn: Babs Jensen\n" +
                "sn: Jensen\n" +
                "uid: bjensen\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "description: A big sailing fan.\n" +
                "\n" +
                "dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Bjorn Jensen\n" +
                "sn: Jensen\n" +
                "telephonenumber: +1 408 555 1212";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 2, entries.size() );

        // Entry 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com", entry.getDn().getName() );

        Attribute attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = entry.get( "cn" );
        assertTrue( attr.contains( "Barbara Jensen" ) );
        assertTrue( attr.contains( "Barbara J Jensen" ) );
        assertTrue( attr.contains( "Babs Jensen" ) );

        attr = entry.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = entry.get( "uid" );
        assertTrue( attr.contains( "bjensen" ) );

        attr = entry.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = entry.get( "description" );
        assertTrue( attr.contains( "A big sailing fan." ) );

        // Entry 2
        entry = entries.get( 1 );
        assertTrue( entry.isLdifContent() );

        attr = entry.get( "dn" );
        assertEquals( "cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com", entry.getDn().getName() );

        attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = entry.get( "cn" );
        assertTrue( attr.contains( "Bjorn Jensen" ) );

        attr = entry.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = entry.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );
    }


    @Test
    public void testLdifParserRFC2849Sample2() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Barbara Jensen\n" +
                "cn: Barbara J Jensen\n" +
                "cn: Babs Jensen\n" +
                "sn: Jensen\n" +
                "uid: bjensen\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "description:Babs is a big sailing fan, and travels extensively in sea\n" +
                " rch of perfect sailing conditions.\n" +
                "title:Product Manager, Rod and Reel Division";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com", entry.getDn().getName() );

        Attribute attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = entry.get( "cn" );
        assertTrue( attr.contains( "Barbara Jensen" ) );
        assertTrue( attr.contains( "Barbara J Jensen" ) );
        assertTrue( attr.contains( "Babs Jensen" ) );

        attr = entry.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = entry.get( "uid" );
        assertTrue( attr.contains( "bjensen" ) );

        attr = entry.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = entry.get( "description" );
        assertTrue( attr
            .contains( "Babs is a big sailing fan, and travels extensively in search of perfect sailing conditions." ) );

        attr = entry.get( "title" );
        assertTrue( attr.contains( "Product Manager, Rod and Reel Division" ) );
    }


    @Test
    public void testLdifParserRFC2849Sample3() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Gern Jensen\n" +
                "cn: Gern O Jensen\n" +
                "sn: Jensen\n" +
                "uid: gernj\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "description:: V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVl\n" +
                " IGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdG\n" +
                " VyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQg\n" +
                " b3V0IG1vcmUu";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com", entry.getDn().getName() );

        Attribute attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = entry.get( "cn" );
        assertTrue( attr.contains( "Gern Jensen" ) );
        assertTrue( attr.contains( "Gern O Jensen" ) );

        attr = entry.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = entry.get( "uid" );
        assertTrue( attr.contains( "gernj" ) );

        attr = entry.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = entry.get( "description" );
        assertTrue( attr
            .contains( "What a careful reader you are!  This value is base-64-encoded because it has a control character in it (a CR).\r  By the way, you should really get out more."
                .getBytes( StandardCharsets.UTF_8 ) ) );
    }


    @Test
    public void testLdifParserRFC2849Sample3VariousSpacing() throws Exception, Exception
    {
        String ldif =
            "version:1\n" +
                "dn:cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com  \n" +
                "objectclass:top\n" +
                "objectclass:   person   \n" +
                "objectclass:organizationalPerson\n" +
                "cn:Gern Jensen\n" +
                "cn:Gern O Jensen\n" +
                "sn:Jensen\n" +
                "uid:gernj\n" +
                "telephonenumber:+1 408 555 1212  \n" +
                "description::  V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVl\n" +
                " IGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdG\n" +
                " VyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQg\n" +
                " b3V0IG1vcmUu  ";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        assertEquals( "cn=Gern Jensen, ou=Product Testing, dc=airius, dc=com", entry.getDn().getName() );

        Attribute attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = entry.get( "cn" );
        assertTrue( attr.contains( "Gern Jensen" ) );
        assertTrue( attr.contains( "Gern O Jensen" ) );

        attr = entry.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = entry.get( "uid" );
        assertTrue( attr.contains( "gernj" ) );

        attr = entry.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = entry.get( "description" );
        assertTrue( attr
            .contains( "What a careful reader you are!  This value is base-64-encoded because it has a control character in it (a CR).\r  By the way, you should really get out more."
                .getBytes( StandardCharsets.UTF_8 ) ) );
    }


    @Test
    public void testLdifParserRFC2849Sample4() throws Exception, Exception
    {
        String ldif =
            "version: 1\n"
                +
                "dn:: b3U95Za25qWt6YOoLG89QWlyaXVz\n"
                +
                "# dn:: ou=���������,o=Airius\n"
                +
                "objectclass: top\n"
                +
                "objectclass: organizationalUnit\n"
                +
                "ou:: 5Za25qWt6YOo\n"
                +
                "# ou:: ���������\n"
                +
                "ou;lang-ja:: 5Za25qWt6YOo\n"
                +
                "# ou;lang-ja:: ���������\n"
                +
                "ou;lang-ja;phonetic:: 44GI44GE44GO44KH44GG44G2\n"
                +
                "# ou;lang-ja:: ������������������\n"
                +
                "ou;lang-en: Sales\n"
                +
                "description: Japanese office\n"
                +
                "\n"
                +
                "dn:: dWlkPXJvZ2FzYXdhcmEsb3U95Za25qWt6YOoLG89QWlyaXVz\n"
                +
                "# dn:: uid=rogasawara,ou=���������,o=Airius\n"
                +
                "userpassword: {SHA}O3HSv1MusyL4kTjP+HKI5uxuNoM=\n"
                +
                "objectclass: top\n"
                +
                "objectclass: person\n"
                +
                "objectclass: organizationalPerson\n"
                +
                "objectclass: inetOrgPerson\n"
                +
                "uid: rogasawara\n"
                +
                "mail: rogasawara@airius.co.jp\n"
                +
                "givenname;lang-ja:: 44Ot44OJ44OL44O8\n"
                +
                "# givenname;lang-ja:: ������������\n"
                +
                "sn;lang-ja:: 5bCP56yg5Y6f\n"
                +
                "# sn;lang-ja:: ���������\n"
                +
                "cn;lang-ja:: 5bCP56yg5Y6fIOODreODieODi+ODvA==\n"
                +
                "# cn;lang-ja:: ��������� ������������\n"
                +
                "title;lang-ja:: 5Za25qWt6YOoIOmDqOmVtw==\n"
                +
                "# title;lang-ja:: ��������� ������\n"
                +
                "preferredlanguage: ja\n"
                +
                "givenname:: 44Ot44OJ44OL44O8\n"
                +
                "# givenname:: ������������\n"
                +
                "sn:: 5bCP56yg5Y6f\n"
                +
                "# sn:: ���������\n"
                +
                "cn:: 5bCP56yg5Y6fIOODreODieODi+ODvA==\n"
                +
                "# cn:: ��������� ������������\n"
                +
                "title:: 5Za25qWt6YOoIOmDqOmVtw==\n"
                +
                "# title:: ��������� ������\n"
                +
                "givenname;lang-ja;phonetic:: 44KN44Gp44Gr44O8\n"
                +
                "# givenname;lang-ja;phonetic:: ������������\n"
                +
                "sn;lang-ja;phonetic:: 44GK44GM44GV44KP44KJ\n"
                +
                "# sn;lang-ja;phonetic:: ���������������\n"
                +
                "cn;lang-ja;phonetic:: 44GK44GM44GV44KP44KJIOOCjeOBqeOBq+ODvA==\n"
                +
                "# cn;lang-ja;phonetic:: ��������������� ������������\n"
                +
                "title;lang-ja;phonetic:: 44GI44GE44GO44KH44GG44G2IOOBtuOBoeOCh+OBhg==\n" +
                "# title;lang-ja;phonetic::\n" +
                "# ������������������ ������������\n" +
                "givenname;lang-en: Rodney\n" +
                "sn;lang-en: Ogasawara\n" +
                "cn;lang-en: Rodney Ogasawara\n" +
                "title;lang-en: Sales, Director\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        String[][][] values =
            {
                {
                    { "dn", "ou=\u55b6\u696d\u90e8,o=Airius" }, // 55b6 = ���, 696d = ���, 90e8 = ���
                        { "objectclass", "top" },
                        { "objectclass", "organizationalUnit" },
                        { "ou", "\u55b6\u696d\u90e8" },
                        { "ou;lang-ja", "\u55b6\u696d\u90e8" },
                        { "ou;lang-ja;phonetic", "\u3048\u3044\u304e\u3087\u3046\u3076" }, // 3048 = ���, 3044 = ���, 304e = ���
                        // 3087 = ���, 3046 = ���, 3076 = ���
                        { "ou;lang-en", "Sales" },
                        { "description", "Japanese office" } },
                {
                    { "dn", "uid=rogasawara,ou=\u55b6\u696d\u90e8,o=Airius" },
                    { "userpassword", "{SHA}O3HSv1MusyL4kTjP+HKI5uxuNoM=" },
                    { "objectclass", "top" },
                    { "objectclass", "person" },
                    { "objectclass", "organizationalPerson" },
                    { "objectclass", "inetOrgPerson" },
                    { "uid", "rogasawara" },
                    { "mail", "rogasawara@airius.co.jp" },
                    { "givenname;lang-ja", "\u30ed\u30c9\u30cb\u30fc" }, // 30ed = ���, 30c9 = ���, 30cb = ���, 30fc = ���
                        { "sn;lang-ja", "\u5c0f\u7b20\u539f" }, // 5c0f = ���, 7b20 = ���, 539f = ���
                        { "cn;lang-ja", "\u5c0f\u7b20\u539f \u30ed\u30c9\u30cb\u30fc" },
                        { "title;lang-ja", "\u55b6\u696d\u90e8 \u90e8\u9577" }, // 9577 = ���
                        { "preferredlanguage", "ja" },
                        { "givenname", "\u30ed\u30c9\u30cb\u30fc" },
                        { "sn", "\u5c0f\u7b20\u539f" },
                        { "cn", "\u5c0f\u7b20\u539f \u30ed\u30c9\u30cb\u30fc" },
                        { "title", "\u55b6\u696d\u90e8 \u90e8\u9577" },
                        { "givenname;lang-ja;phonetic", "\u308d\u3069\u306b\u30fc" }, // 308d = ���,3069 = ���, 306b = ���
                        { "sn;lang-ja;phonetic", "\u304a\u304c\u3055\u308f\u3089" }, // 304a = ���, 304c = ���,3055 = ���,308f = ���, 3089 = ���
                        { "cn;lang-ja;phonetic", "\u304a\u304c\u3055\u308f\u3089 \u308d\u3069\u306b\u30fc" },
                        { "title;lang-ja;phonetic", "\u3048\u3044\u304e\u3087\u3046\u3076 \u3076\u3061\u3087\u3046" }, // 304E = ���, 3061 = ���
                        { "givenname;lang-en", "Rodney" },
                        { "sn;lang-en", "Ogasawara" },
                        { "cn;lang-en", "Rodney Ogasawara" },
                        { "title;lang-en", "Sales, Director" } } };

        assertEquals( 2, entries.size() );

        // Entry 1
        for ( int i = 0; i < entries.size(); i++ )
        {
            LdifEntry entry = entries.get( i );
            assertTrue( entry.isLdifContent() );

            for ( int j = 0; j < values[i].length; j++ )
            {
                if ( "dn".equalsIgnoreCase( values[i][j][0] ) )
                {
                    assertEquals( values[i][j][1], entry.getDn().getName() );
                }
                else
                {
                    Attribute attr = entry.get( values[i][j][0] );

                    if ( attr.contains( values[i][j][1] ) )
                    {
                        assertTrue( true );
                    }
                    else
                    {
                        assertTrue( attr.contains( values[i][j][1].getBytes( StandardCharsets.UTF_8 ) ) );
                    }
                }
            }
        }
    }


    @Test
    public void testLdifParserRFC2849Sample5() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Horatio Jensen, ou=Product Testing, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Horatio Jensen\n" +
                "cn: Horatio N Jensen\n" +
                "sn: Jensen\n" +
                "uid: hjensen\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "jpegphoto:< file:" +
                HJENSEN_JPEG_FILE.getAbsolutePath() +
                "\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        String[][] values =
            {
                { "dn", "cn=Horatio Jensen, ou=Product Testing, dc=airius, dc=com" },
                { "objectclass", "top" },
                { "objectclass", "person" },
                { "objectclass", "organizationalPerson" },
                { "cn", "Horatio Jensen" },
                { "cn", "Horatio N Jensen" },
                { "sn", "Jensen" },
                { "uid", "hjensen" },
                { "telephonenumber", "+1 408 555 1212" },
                { "jpegphoto", null } };

        assertEquals( 1, entries.size() );

        // Entry 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );

        for ( int i = 0; i < values.length; i++ )
        {
            if ( "dn".equalsIgnoreCase( values[i][0] ) )
            {
                assertEquals( values[i][1], entry.getDn().getName() );
            }
            else if ( "jpegphoto".equalsIgnoreCase( values[i][0] ) )
            {
                Attribute attr = entry.get( values[i][0] );
                assertEquals( Strings.dumpBytes( data ), Strings.dumpBytes( attr.getBytes() ) );
            }
            else
            {
                Attribute attr = entry.get( values[i][0] );

                if ( attr.contains( values[i][1] ) )
                {
                    assertTrue( true );
                }
                else
                {
                    assertTrue( attr.contains( values[i][1].getBytes( StandardCharsets.UTF_8 ) ) );
                }
            }
        }
    }


    @Test
    public void testLdifParserRFC2849Sample5WithSizeLimit() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Horatio Jensen, ou=Product Testing, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Horatio Jensen\n" +
                "cn: Horatio N Jensen\n" +
                "sn: Jensen\n" +
                "uid: hjensen\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "jpegphoto:< file:" +
                HJENSEN_JPEG_FILE.getAbsolutePath() +
                "\n";

        LdifReader reader = new LdifReader();
        reader.setSizeLimit( 128 );
        reader.close();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( ne.getMessage().startsWith( I18n.ERR_13442_ERROR_PARSING_LDIF_BUFFER.getErrorCode() ),
                        I18n.err( I18n.ERR_13442_ERROR_PARSING_LDIF_BUFFER ) );
        }
    }


    @Test
    public void testLdifParserRFC2849Sample6() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                // First entry modification : ADD
                "# Add a new entry\n" +
                "dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com\n" +
                "changetype: add\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Fiona Jensen\n" +
                "sn: Jensen\n" +
                "uid: fiona\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "jpegphoto:< file:" +
                FIONA_JPEG_FILE.getAbsolutePath() +
                "\n" +
                "\n"
                +
                // Second entry modification : DELETE
                "# Delete an existing entry\n" +
                "dn: cn=Robert Jensen, ou=Marketing, dc=airius, dc=com\n" +
                "changetype: delete\n" +
                "\n"
                +
                // Third entry modification : MODRDN
                "# Modify an entry's relative distinguished name\n" +
                "dn: cn=Paul Jensen, ou=Product Development, dc=airius, dc=com\n" +
                "changetype: modrdn\n" +
                "newrdn: cn=Paula Jensen\n" +
                "deleteoldrdn: 1\n" +
                "\n"
                +
                // Forth entry modification : MODRDN
                "# Rename an entry and move all of its children to a new location in\n" +
                "# the directory tree (only implemented by LDAPv3 servers).\n" +
                "dn: ou=PD Accountants, ou=Product Development, dc=airius, dc=com\n" +
                "changetype: moddn\n" +
                "newrdn: ou=Product Development Accountants\n" +
                "deleteoldrdn: 0\n" +
                "newsuperior: ou=Accounting, dc=airius, dc=com\n" +
                "# Modify an entry: add an additional value to the postaladdress\n" +
                "# attribute, completely delete the description attribute, replace\n" +
                "# the telephonenumber attribute with two values, and delete a specific\n" +
                "# value from the facsimiletelephonenumber attribute\n" +
                "\n"
                +
                // Fitfh entry modification : MODIFY
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
                "\n"
                +
                // Sixth entry modification : MODIFY
                "# Modify an entry: replace the postaladdress attribute with an empty\n" +
                "# set of values (which will cause the attribute to be removed), and\n" +
                "# delete the entire description attribute. Note that the first will\n" +
                "# always succeed, while the second will only succeed if at least\n" +
                "# one value for the description attribute is present.\n" +
                "dn: cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com\n" +
                "changetype: modify\n" +
                "replace: postaladdress\n" +
                "-\n" +
                "delete: description\n" +
                "-\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        String[][][] values =
            {
                // First entry modification : ADD
                {
                    { "dn", "cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com" },
                    { "objectclass", "top" },
                    { "objectclass", "person" },
                    { "objectclass", "organizationalPerson" },
                    { "cn", "Fiona Jensen" },
                    { "sn", "Jensen" },
                    { "uid", "fiona" },
                    { "telephonenumber", "+1 408 555 1212" },
                    { "jpegphoto", "" } },
                    // Second entry modification : DELETE
                    {
                        { "dn", "cn=Robert Jensen, ou=Marketing, dc=airius, dc=com" } },
                    // Third entry modification : MODRDN
                    {
                        { "dn", "cn=Paul Jensen, ou=Product Development, dc=airius, dc=com" },
                        { "cn=Paula Jensen" } },
                    // Forth entry modification : MODRDN
                    {
                        { "dn", "ou=PD Accountants, ou=Product Development, dc=airius, dc=com" },
                        { "ou=Product Development Accountants" },
                        { "ou=Accounting, dc=airius, dc=com" } },
                    // Fitfh entry modification : MODIFY
                    {
                        { "dn", "cn=Paula Jensen, ou=Product Development, dc=airius, dc=com" },
                        // add
                        { "postaladdress", "123 Anystreet $ Sunnyvale, CA $ 94086" },
                            // delete
                            { "description" },
                            // replace
                            { "telephonenumber", "+1 408 555 1234", "+1 408 555 5678" },
                            // delete
                            { "facsimiletelephonenumber", "+1 408 555 9876" }, },
                    // Sixth entry modification : MODIFY
                    {
                        { "dn", "cn=Ingrid Jensen, ou=Product Support, dc=airius, dc=com" },
                        // replace
                        { "postaladdress" },
                            // delete
                            { "description" } } };

        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isChangeAdd() );

        for ( int i = 0; i < values.length; i++ )
        {
            if ( "dn".equalsIgnoreCase( values[0][i][0] ) )
            {
                assertEquals( values[0][i][1], entry.getDn().getName() );
            }
            else if ( "jpegphoto".equalsIgnoreCase( values[0][i][0] ) )
            {
                Attribute attr = entry.get( values[0][i][0] );
                assertEquals( Strings.dumpBytes( data ), Strings.dumpBytes( attr.getBytes() ) );
            }
            else
            {
                Attribute attr = entry.get( values[0][i][0] );

                if ( attr.contains( values[0][i][1] ) )
                {
                    assertTrue( true );
                }
                else
                {
                    assertTrue( attr.contains( values[0][i][1].getBytes( StandardCharsets.UTF_8 ) ) );
                }
            }
        }

        // Second entry
        entry = entries.get( 1 );
        assertTrue( entry.isChangeDelete() );
        assertEquals( values[1][0][1], entry.getDn().getName() );

        // Third entry
        entry = entries.get( 2 );
        assertTrue( entry.isChangeModRdn() );
        assertEquals( values[2][0][1], entry.getDn().getName() );
        assertEquals( values[2][1][0], entry.getNewRdn() );
        assertTrue( entry.isDeleteOldRdn() );

        // Forth entry
        entry = entries.get( 3 );
        assertTrue( entry.isChangeModDn() );
        assertEquals( values[3][0][1], entry.getDn().getName() );
        assertEquals( values[3][1][0], entry.getNewRdn() );
        assertFalse( entry.isDeleteOldRdn() );
        assertEquals( values[3][2][0], entry.getNewSuperior() );

        // Fifth entry
        entry = entries.get( 4 );
        List<Modification> modifs = entry.getModifications();

        assertTrue( entry.isChangeModify() );
        assertEquals( values[4][0][1], entry.getDn().getName() );

        // "add: postaladdress"
        // "postaladdress: 123 Anystreet $ Sunnyvale, CA $ 94086"
        Modification item = modifs.get( 0 );
        assertEquals( ModificationOperation.ADD_ATTRIBUTE, item.getOperation() );
        assertEquals( values[4][1][0], item.getAttribute().getId() );
        assertTrue( item.getAttribute().contains( values[4][1][1] ) );

        // "delete: description\n" +
        item = modifs.get( 1 );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, item.getOperation() );
        assertEquals( values[4][2][0], item.getAttribute().getId() );

        // "replace: telephonenumber"
        // "telephonenumber: +1 408 555 1234"
        // "telephonenumber: +1 408 555 5678"
        item = modifs.get( 2 );
        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, item.getOperation() );

        assertEquals( values[4][3][0], item.getAttribute().getId() );
        assertTrue( item.getAttribute().contains( values[4][3][1], values[4][3][2] ) );

        // "delete: facsimiletelephonenumber"
        // "facsimiletelephonenumber: +1 408 555 9876"
        item = modifs.get( 3 );

        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, item.getOperation() );

        assertEquals( values[4][4][0], item.getAttribute().getId() );
        assertTrue( item.getAttribute().contains( values[4][4][1] ) );

        // Sixth entry
        entry = entries.get( 5 );
        modifs = entry.getModifications();

        assertTrue( entry.isChangeModify() );
        assertEquals( values[5][0][1], entry.getDn().getName() );

        // "replace: postaladdress"
        item = modifs.get( 0 );
        assertEquals( ModificationOperation.REPLACE_ATTRIBUTE, item.getOperation() );
        assertEquals( values[5][1][0], item.getAttribute().getId() );

        // "delete: description"
        item = modifs.get( 1 );
        assertEquals( ModificationOperation.REMOVE_ATTRIBUTE, item.getOperation() );
        assertEquals( values[5][2][0], item.getAttribute().getId() );
    }


    @Test
    public void testLdifParserRFC2849Sample7() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113556.1.4.805 true\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "ou=Product Development, dc=airius, dc=com", entry.getDn().getName() );
        assertTrue( entry.isChangeDelete() );

        // Check the control
        Control control = entry.getControl( "1.2.840.113556.1.4.805" );

        assertEquals( "1.2.840.113556.1.4.805", control.getOid() );
        assertTrue( control.isCritical() );
    }


    @Test
    public void testLdifParserRFC2849Sample7NoValueNoCritical() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113556.1.4.805\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "ou=Product Development, dc=airius, dc=com", entry.getDn().getName() );
        assertTrue( entry.isChangeDelete() );

        // Check the control
        Control control = entry.getControl( "1.2.840.113556.1.4.805" );

        assertEquals( "1.2.840.113556.1.4.805", control.getOid() );
        assertFalse( control.isCritical() );
    }


    @Test
    public void testLdifParserRFC2849Sample7NoCritical() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113556.1.4.805:control-value\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "ou=Product Development, dc=airius, dc=com", entry.getDn().getName() );
        assertTrue( entry.isChangeDelete() );

        // Check the control
        LdifControl control = entry.getControl( "1.2.840.113556.1.4.805" );

        assertEquals( "1.2.840.113556.1.4.805", control.getOid() );
        assertFalse( control.isCritical() );
        assertEquals( "control-value", Strings.utf8ToString( control.getValue() ) );
    }


    @Test
    public void testLdifParserRFC2849Sample7NoOid() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: true\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    @Test
    public void testLdifParserRFC2849Sample7BadOid() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "# Delete an entry. The operation will attach the LDAPv3\n" +
                "# Tree Delete Control defined in [9]. The criticality\n" +
                "# field is \"true\" and the controlValue field is\n" +
                "# absent, as required by [9].\n" +
                "dn: ou=Product Development, dc=airius, dc=com\n" +
                "control: 1.2.840.113A556.1.4.805 true\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();

        try
        {
            reader.parseLdif( ldif );
            fail();
        }
        catch ( Exception ne )
        {
            assertTrue( true );
        }
        finally
        {
            reader.close();
        }
    }


    @Test
    public void testLdifReaderDirServer() throws Exception, Exception
    {
        String ldif =
            "# -------------------------------------------------------------------\n" +
                "#\n" +
                "#  Licensed to the Apache Software Foundation (ASF) under one\n" +
                "#  or more contributor license agreements.  See the NOTICE file\n" +
                "#  distributed with this work for additional information\n" +
                "#  regarding copyright ownership.  The ASF licenses this file\n" +
                "#  to you under the Apache License, Version 2.0 (the\n" +
                "#  \"License\"); you may not use this file except in compliance\n" +
                "#  with the License.  You may obtain a copy of the License at\n" +
                "#  \n" +
                "#    https://www.apache.org/licenses/LICENSE-2.0\n" +
                "#  \n" +
                "#  Unless required by applicable law or agreed to in writing,\n" +
                "#  software distributed under the License is distributed on an\n" +
                "#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n" +
                "#  KIND, either express or implied.  See the License for the\n" +
                "#  specific language governing permissions and limitations\n" +
                "#  under the License. \n" +
                "#  \n" +
                "#\n" +
                "# EXAMPLE.COM is freely and reserved for testing according to this RFC:\n" +
                "#\n" +
                "# http://www.rfc-editor.org/rfc/rfc2606.txt\n" +
                "#\n" +
                "# -------------------------------------------------------------------\n" +
                "\n" +
                "dn: ou=Users, dc=example, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: organizationalunit\n" +
                "ou: Users";

        LdifReader reader = new LdifReader();

        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "ou=Users, dc=example, dc=com", entry.getDn().getName() );

        Attribute attr = entry.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "organizationalunit" ) );

        attr = entry.get( "ou" );
        assertTrue( attr.contains( "Users" ) );
    }


    @Test
    public void testLdifParserCommentsEmptyLines() throws Exception, Exception
    {
        String ldif =
            "#\n"
                +
                "#  Licensed to the Apache Software Foundation (ASF) under one\n"
                +
                "#  or more contributor license agreements.  See the NOTICE file\n"
                +
                "#  distributed with this work for additional information\n"
                +
                "#  regarding copyright ownership.  The ASF licenses this file\n"
                +
                "#  to you under the Apache License, Version 2.0 (the\n"
                +
                "#  \"License\"); you may not use this file except in compliance\n"
                +
                "#  with the License.  You may obtain a copy of the License at\n"
                +
                "#  \n"
                +
                "#    https://www.apache.org/licenses/LICENSE-2.0\n"
                +
                "#  \n"
                +
                "#  Unless required by applicable law or agreed to in writing,\n"
                +
                "#  software distributed under the License is distributed on an\n"
                +
                "#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n"
                +
                "#  KIND, either express or implied.  See the License for the\n"
                +
                "#  specific language governing permissions and limitations\n"
                +
                "#  under the License. \n"
                +
                "#  \n"
                +
                "#\n"
                +
                "#\n"
                +
                "#   EXAMPLE.COM is freely and reserved for testing according to this RFC:\n"
                +
                "#\n"
                +
                "#   http://www.rfc-editor.org/rfc/rfc2606.txt\n"
                +
                "#\n"
                +
                "#\n"
                +
                "\n"
                +
                "#\n"
                +
                "# This ACI allows brouse access to the root suffix and one level below that to anyone.\n"
                +
                "# At this level there is nothing critical exposed.  Everything that matters is one or\n"
                +
                "# more levels below this.\n"
                +
                "#\n"
                +
                "\n"
                +
                "dn: cn=browseRootAci,dc=example,dc=com\n"
                +
                "objectClass: top\n"
                +
                "objectClass: subentry\n"
                +
                "objectClass: accessControlSubentry\n"
                +
                "subtreeSpecification: { maximum 1 }\n"
                +
                "prescriptiveACI: { identificationTag \"browseRoot\", precedence 100, authenticationLevel none, itemOrUserFirst userFirst: { userClasses { allUsers }, userPermissions { { protectedItems {entry}, grantsAndDenials { grantReturnDN, grantBrowse } } } } }\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertEquals( "cn=browseRootAci,dc=example,dc=com", entry.getDn().getName() );
        Attribute attr = entry.get( "objectClass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( SchemaConstants.SUBENTRY_OC ) );
        assertTrue( attr.contains( "accessControlSubentry" ) );

        attr = entry.get( "subtreeSpecification" );
        assertTrue( attr.contains( "{ maximum 1 }" ) );

        attr = entry.get( "prescriptiveACI" );
        assertTrue( attr
            .contains( "{ identificationTag \"browseRoot\", precedence 100, authenticationLevel none, itemOrUserFirst userFirst: { userClasses { allUsers }, userPermissions { { protectedItems {entry}, grantsAndDenials { grantReturnDN, grantBrowse } } } } }" ) );
    }


    @Test
    public void testRemoveAttribute() throws Exception
    {
        String ldif =
            "version: 1\n" +
                "dn: cn=Horatio Jensen, ou=Product Testing, dc=airius, dc=com\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Horatio Jensen\n" +
                "cn: Horatio N Jensen\n" +
                "sn: Jensen\n" +
                "uid: hjensen\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "jpegphoto:< file:" +
                HJENSEN_JPEG_FILE.getAbsolutePath() +
                "\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry = entries.get( 0 );

        assertNotNull( entry.get( "uid" ) );
        entry.removeAttribute( "uid" );
        assertNull( entry.get( "uid" ) );
    }


    @Test
    public void testChangeTypeAdd() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: add\n" +
                "attr1: ATTR1\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeAdd() );

        assertEquals( 1, entry.getEntry().size() );

        Attribute attr = entry.get( "attr1" );
        assertTrue( attr.contains( "ATTR1" ) );
    }


    @Test
    public void testChangeTypeAddAttrs2Values() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: add\n" +
                "attr1: ATTR1\n" +
                "attr1: ATTR2\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeAdd() );

        assertEquals( 1, entry.getEntry().size() );

        Attribute attr = entry.get( "attr1" );
        assertEquals( 2, attr.size() );
        assertTrue( attr.contains( "ATTR1" ) );
        assertTrue( attr.contains( "ATTR2" ) );
    }


    @Test
    public void testChangeTypeAdd2Attrs2Values() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: add\n" +
                "attr1: ATTR1\n" +
                "attr1: ATTR2\n" +
                "attr2: ATTR1\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeAdd() );

        assertEquals( 2, entry.getEntry().size() );

        Attribute attr = entry.get( "attr1" );
        assertEquals( 2, attr.size() );
        assertTrue( attr.contains( "ATTR1" ) );
        assertTrue( attr.contains( "ATTR2" ) );

        Attribute attr2 = entry.get( "attr2" );
        assertEquals( 1, attr2.size() );
        assertTrue( attr2.contains( "ATTR1" ) );
    }


    @Test
    public void testChangeTypeDelete() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeDelete() );
    }


    @Test
    public void testLdifChangeDeleteWithControl() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "control: 1.1.1\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeDelete() );

        assertTrue( entry.hasControls() );
        assertEquals( 1, entry.getControls().size() );

        LdifControl control = entry.getControl( "1.1.1" );

        assertEquals( "1.1.1", control.getOid() );
        assertFalse( control.isCritical() );
        assertNull( control.getValue() );
    }


    @Test
    public void testLdifChangeDeleteWithControls() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "control: 1.1.1\n" +
                "control: 1.1.2 true\n" +
                "control: 1.1.3:ABCDEF\n" +
                "control: 1.1.4 true:ABCDEF\n" +
                "control: 1.1.5::RW1tYW51ZWwgTMOpY2hhcm55\n" +
                "control: 1.1.6 true::RW1tYW51ZWwgTMOpY2hhcm55\n" +
                "control: 1.1.7 true:a control\n" +
                "changetype: delete\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertEquals( 1, entries.size() );

        // Entry
        LdifEntry entry = entries.get( 0 );

        assertEquals( "dc=example,dc=com", entry.getDn().getName() );

        assertTrue( entry.isLdifChange() );
        assertTrue( entry.isChangeDelete() );

        assertTrue( entry.hasControls() );
        assertEquals( 7, entry.getControls().size() );

        // First control
        LdifControl control = entry.getControl( "1.1.1" );

        assertEquals( "1.1.1", control.getOid() );
        assertFalse( control.isCritical() );
        assertNull( control.getValue() );

        // Second control
        control = entry.getControl( "1.1.2" );

        assertEquals( "1.1.2", control.getOid() );
        assertTrue( control.isCritical() );
        assertNull( control.getValue() );

        // Third control
        control = entry.getControl( "1.1.3" );

        assertEquals( "1.1.3", control.getOid() );
        assertFalse( control.isCritical() );
        assertEquals( "ABCDEF", Strings.utf8ToString( control.getValue() ) );

        // Forth control
        control = entry.getControl( "1.1.4" );

        assertEquals( "1.1.4", control.getOid() );
        assertTrue( control.isCritical() );
        assertEquals( "ABCDEF", Strings.utf8ToString( control.getValue() ) );

        // Fifth control
        control = entry.getControl( "1.1.5" );

        assertEquals( "1.1.5", control.getOid() );
        assertFalse( control.isCritical() );
        assertEquals( "Emmanuel L\u00e9charny", Strings.utf8ToString( control.getValue() ) );

        // Sixth control
        control = entry.getControl( "1.1.6" );

        assertEquals( "1.1.6", control.getOid() );
        assertTrue( control.isCritical() );
        assertEquals( "Emmanuel L\u00e9charny", Strings.utf8ToString( control.getValue() ) );

        // Seventh control
        control = entry.getControl( "1.1.7" );

        assertEquals( "1.1.7", control.getOid() );
        assertTrue( control.isCritical() );
        assertEquals( "a control", Strings.utf8ToString( control.getValue() ) );
    }


    @Test
    public void testChangeTypeDeleteBadEntry() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: delete\n" +
                "attr1: test";

        try ( LdifReader reader = new LdifReader() )
        {
            assertThrows( LdapLdifException.class, () ->
            {
                reader.parseLdif( ldif );
            } );
        }
    }


    @Test
    public void testLdifContentWithControl() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "control: 1.1.1\n" +
                "attr1: test";

        try ( LdifReader reader = new LdifReader() )
        {
            assertThrows( LdapLdifException.class, () ->
            {
                reader.parseLdif( ldif );
            } );
        }
    }


    /**
     * Test that we can parse a LDIF with a modify changeType and see if the
     * empty attribute and the attribute deletion aren't producing the same Modify entry
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserChangeTypeModifyDeleteEmptyValue() throws Exception
    {
        // test that mixed case attr ids work at all
        String ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "-\n" +
                "\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: modify\n" +
                "delete: userPassword\n" +
                "userPassword:\n" +
                "-";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        LdifEntry entry1 = entries.get( 0 );
        Modification modification = entry1.getModifications().get( 0 );
        assertEquals( 0, modification.getAttribute().size() );
        assertNull( modification.getAttribute().get() );

        LdifEntry entry2 = entries.get( 1 );
        modification = entry2.getModifications().get( 0 );
        assertEquals( 1, modification.getAttribute().size() );
        assertNotNull( modification.getAttribute().get() );
        assertNull( modification.getAttribute().getBytes() );
    }


    /**
     * Test lengths when multiple entries are present
     *
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserLengthAndOffset() throws Exception
    {
        String ldif1 = "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
            "cn: app1\n" +
            "objectClass: top\n" +
            "objectClass: apApplication\n" +
            "displayName:   app1   \n" +
            "dependencies:\n" +
            "envVars:\n";

        String comment = "# This comment was copied. Delete an entry. The operation will attach the LDAPv3\n" +
            "# Tree Delete Control defined in [9]. The criticality\n" +
            "# field is \"true\" and the controlValue field is\n" +
            "# absent, as required by [9].\n";

        String version = "version:   1\n";

        String ldif =
            version +
                ldif1 +
                "\n" +
                comment +
                ldif1 + "\n";

        LdifReader reader = new LdifReader();

        List<LdifEntry> lstEntries = null;

        try
        {
            lstEntries = reader.parseLdif( ldif );
        }
        catch ( Exception ne )
        {
            fail();
        }
        finally
        {
            reader.close();
        }

        LdifEntry entry1 = lstEntries.get( 0 );

        assertEquals( version.length() + ldif1.length(), entry1.getLengthBeforeParsing() );

        LdifEntry entry2 = lstEntries.get( 1 );

        assertEquals( ldif1.length() + comment.length(), entry2.getLengthBeforeParsing() );

        byte[] data = Strings.getBytesUtf8( ldif );

        String ldif1Bytes = new String( data, ( int ) entry1.getOffset(), entry1.getLengthBeforeParsing(),
            StandardCharsets.UTF_8 );
        assertNotNull( reader.parseLdif( ldif1Bytes ).get( 0 ) );

        String ldif2Bytes = new String( data, ( int ) entry2.getOffset(), entry2.getLengthBeforeParsing(),
            StandardCharsets.UTF_8 );
        assertNotNull( reader.parseLdif( ldif2Bytes ).get( 0 ) );

        File file = File.createTempFile( "offsetTest", "ldif" );
        file.deleteOnExit();
        OutputStreamWriter writer = new OutputStreamWriter( new FileOutputStream( file ), Charset.defaultCharset() );
        writer.write( ldif );
        writer.close();

        RandomAccessFile raf = new RandomAccessFile( file, "r" );

        LdifReader ldifReader = new LdifReader( file );

        LdifEntry rafEntry1 = ldifReader.next();

        data = new byte[rafEntry1.getLengthBeforeParsing()];
        raf.read( data, ( int ) rafEntry1.getOffset(), data.length );

        reader = new LdifReader();
        LdifEntry reReadeRafEntry1 = reader.parseLdif( new String( data, Charset.defaultCharset() ) ).get( 0 );
        assertNotNull( reReadeRafEntry1 );
        assertEquals( rafEntry1.getOffset(), reReadeRafEntry1.getOffset() );
        assertEquals( rafEntry1.getLengthBeforeParsing(), reReadeRafEntry1.getLengthBeforeParsing() );
        reader.close();

        LdifEntry rafEntry2 = ldifReader.next();

        data = new byte[rafEntry2.getLengthBeforeParsing()];
        raf.readFully( data, 0, data.length );

        reader = new LdifReader();
        LdifEntry reReadeRafEntry2 = reader.parseLdif( new String( data, Charset.defaultCharset() ) ).get( 0 );
        assertNotNull( reReadeRafEntry2 );
        assertEquals( rafEntry2.getLengthBeforeParsing(), reReadeRafEntry2.getLengthBeforeParsing() );
        reader.close();
        ldifReader.close();
        raf.close();
    }


    @Test
    // for DIRAPI-174
    public void testLineNumber() throws Exception
    {
        String ldif =
            "versionN:   1\n" + // wrong tag name 'versionN'
                "dn: dc=example,dc=com\n" +
                "changetype: delete\n" +
                "attr1: test";

        try ( LdifReader reader = new LdifReader() )
        {
            try
            {
                reader.parseLdif( ldif );
                fail();
            }
            catch ( Exception e )
            {
            }
            
            assertEquals( 1, reader.getLineNumber() );
        }

        ldif =
            "version:   1\n" +
                "d n: dc=example,dc=com\n" + // wrong name "d n"
                "changetype: delete\n" +
                "attr1: test";

        try ( LdifReader reader = new LdifReader() )
        {
            try
            {
                reader.parseLdif( ldif );
                fail();
            }
            catch ( Exception e )
            {
            }
    
            assertEquals( 2, reader.getLineNumber() );
        }

        // wrong changetype
        ldif =
            "version:   1\n" +
                "dn: dc=example,dc=com\n" +
                "changetype: delete\n" +
                "attr1: test";
        
        try ( LdifReader reader = new LdifReader() )
        {
            try
            {
                reader.parseLdif( ldif );
                fail();
            }
            catch ( Exception e )
            {
            }
            
            assertEquals( 4, reader.getLineNumber() );
        }

        ldif =
            "version:   1\n" +
                "dn: cn=app1,ou=applications,ou=conf,dc=apache,dc=org\n" +
                "cn: app1\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app1   \n" +
                "dependencies:\n" +
                "envVars:\n\n" + // watch out the extra newline while counting
                "d n: cn=app2,ou=applications,ou=conf,dc=apache,dc=org\n" + // wrong start
                "cn: app2\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName:   app2   \n" +
                "dependencies:\n" +
                "envVars:";
        
        try ( LdifReader reader = new LdifReader() )
        {
            try
            {
                reader.parseLdif( ldif );
                fail( "shouldn't be parsed" );
            }
            catch ( Exception e )
            {
            }
    
            assertEquals( 10, reader.getLineNumber() );
        }
    }


    @Test
    public void testLdifParserRootDSE() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn:\n" +
                "cn:: YXBwMQ==\n" +
                "objectClass: top\n" +
                "objectClass: apApplication\n" +
                "displayName: app1   \n" +
                "dependencies:\n" +
                "envVars:";

        try ( LdifReader reader = new LdifReader() )
        {
            List<LdifEntry> entries = reader.parseLdif( ldif );
    
            assertNotNull( entries );
    
            LdifEntry entry = entries.get( 0 );
            assertTrue( entry.isLdifContent() );
    
            assertEquals( "", entry.getDn().getName() );
    
            Attribute attr = entry.get( "cn" );
            assertTrue( attr.contains( "app1" ) );
    
            attr = entry.get( "objectclass" );
            assertTrue( attr.contains( "top" ) );
            assertTrue( attr.contains( "apApplication" ) );
    
            attr = entry.get( "displayname" );
            assertTrue( attr.contains( "app1" ) );
    
            attr = entry.get( "dependencies" );
            assertEquals( "", attr.get().getString() );
    
            attr = entry.get( "envvars" );
            assertEquals( "", attr.get().getString() );
        }
    }


    /**
     * Test a LDIF generated by a request with 1.1
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testLdifParserNoAttribute() throws Exception
    {
        String ldif =
            "version:   1\n" +
                "dn: cn=test1\n" +
                "\n" +
                "dn: cn=test2\n" +
                "\n" +
                "dn: cn=test3";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        reader.close();

        assertNotNull( entries );

        // Check test 1
        LdifEntry entry = entries.get( 0 );
        assertTrue( entry.isLdifContent() );
        assertEquals( "cn=test1", entry.getDn().getName() );
        assertEquals( 0, entry.size() );

        // Check test 2
        entry = entries.get( 1 );
        assertTrue( entry.isLdifContent() );
        assertEquals( "cn=test2", entry.getDn().getName() );
        assertEquals( 0, entry.size() );

        // Check test 3
        entry = entries.get( 2 );
        assertTrue( entry.isLdifContent() );
        assertEquals( "cn=test3", entry.getDn().getName() );
        assertEquals( 0, entry.size() );
    }


    @Test
    public void testLdifParserWithUnderscoresAT() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Add a new entry\n" +
                "dn: cn=Fiona Jensen, ou=Marketing, dc=airius, dc=com\n" +
                "changetype: add\n" +
                "objectclass: top\n" +
                "objectclass: person\n" +
                "objectclass: organizationalPerson\n" +
                "cn: Fiona Jensen\n" +
                "sn: Jensen\n" +
                "uid: fiona\n" +
                "telephonenumber: +1 408 555 1212\n" +
                "An_idiot_Attribute: thanks M$ for that";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        LdifEntry entry = entries.get( 0 );
        assertEquals( entry.get( "An_idiot_Attribute" ).getString(), "thanks M$ for that" );
        reader.close();
    }


    @Test
    public void testLdifParserWithMixedATHR() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Add a new entry\n" +
                "dn: cn=DeviceTypes,cn=SDT,cn=prod_81,o=myconfiguration\n" +
                "cn: DeviceTypes\n" +
                "javaClassName: java.lang.String\n" +
                "myconfigstringvalue: P:Phone (except BlackBerry)\n" +
                "myconfigstringvalue:: WjpCbGFja0JlcnJ5w4LCrg==\n" +
                "myconfigstringvalue: 3:Internet only device\n" +
                "objectClass: top\n" +
                "objectClass: javaobject\n" +
                "objectClass: myconfigstringvaluedobject\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        LdifEntry entry = entries.get( 0 );

        // Check that the myconfigstringvalue contains 3 values
        assertEquals( 3, entry.get( "myconfigstringvalue" ).size() );
        assertTrue( entry.get( "myconfigstringvalue" ).isHumanReadable() );

        reader.close();
    }


    @Test
    public void testLdifParserWithMixedATBinary() throws Exception, Exception
    {
        String ldif =
            "version: 1\n" +
                "# Add a new entry\n" +
                "dn: cn=DeviceTypes,cn=SDT,cn=prod_81,o=myconfiguration\n" +
                "cn: DeviceTypes\n" +
                "javaClassName: java.lang.String\n" +
                "myconfigstringvalue:: WjpCbGFja0JlcnJ5w4LCrg==\n" +
                "myconfigstringvalue: P:Phone (except BlackBerry)\n" +
                "myconfigstringvalue: 3:Internet only device\n" +
                "objectClass: top\n" +
                "objectClass: javaobject\n" +
                "objectClass: myconfigstringvaluedobject\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        LdifEntry entry = entries.get( 0 );

        // Check that the myconfigstringvalue contains 3 values
        assertEquals( 3, entry.get( "myconfigstringvalue" ).size() );
        assertFalse( entry.get( "myconfigstringvalue" ).isHumanReadable() );

        reader.close();

    }


    @Test
    public void testLdifParserWithReplaceEmptyValue() throws Exception, Exception
    {
        String ldif =
            "dn: cn=Steven Nguyen,ou=SAP,dc=sap,dc=local\n" +
            "changetype: modify\n" +
            "replace: objectClass\n" +
            "objectClass: top\n" +
            "objectClass: user\n" +
            "objectClass: person\n" +
            "objectClass: organizationalPerson\n" +
            "-\n" +
            "replace: sn\n" +
            "sn: Nguyen Linh\n" +
            "-\n" +
            "replace: url\n" +
            "-\n";

        LdifReader reader = new LdifReader();
        List<LdifEntry> entries = reader.parseLdif( ldif );
        LdifEntry entry = entries.get( 0 );

        assertEquals( ldif, entry.toString() );
        reader.close();
    }


    @Test
    public void testLdifParserWithNullDn() throws Exception, Exception
    {
        String ldif1 =
            "dn: ads-authenticatorid=anonymousauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config\n" +
            "ads-authenticatorid: anonymousauthenticator\n" +
            "objectclass: top\n" +
            "objectclass: ads-base\n" +
            "objectClass: ads-authenticator\n" +
            "objectClass: ads-authenticatorImpl\n" +
            "ads-authenticatorClass: org.apache.directory.server.core.authn.AnonymousAuthenticator\n" +
            "ads-baseDn: \n" +
            "ads-enabled: TRUE";

        String ldif2 =
            "dn: ads-authenticatorid=anonymousauthenticator,ou=authenticators,ads-interceptorId=authenticationInterceptor,ou=interceptors,ads-directoryServiceId=default,ou=config\n" +
            "ads-authenticatorid: anonymousauthenticator\n" +
            "objectclass: top\n" +
            "objectclass: ads-base\n" +
            "objectClass: ads-authenticator\n" +
            "objectClass: ads-authenticatorImpl\n" +
            "ads-authenticatorClass: org.apache.directory.server.core.authn.AnonymousAuthenticator\n" +
            "ads-baseDn:\n" +
            "ads-enabled: TRUE";

        try ( LdifReader reader = new LdifReader() )
        {
            List<LdifEntry> entries1 = reader.parseLdif( ldif1 );
            LdifEntry entry1 = entries1.get( 0 );
    
            List<LdifEntry> entries2 = reader.parseLdif( ldif2 );
            LdifEntry entry2 = entries2.get( 0 );
            assertEquals( entry1, entry2 );
        }
    }
}
