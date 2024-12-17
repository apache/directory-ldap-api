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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.util.FileUtils;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;



/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class LdifAttributesReaderTest
{
    private byte[] data;

    private File HJENSEN_JPEG_FILE = null;
    
    private File jpegFile;
    
    @TempDir
    public File tmpFolder;


    private File createFile( String name, byte[] data ) throws IOException
    {
        jpegFile = File.createTempFile( tmpFolder.toString(), name + ".jpg" );

        DataOutputStream os = new DataOutputStream( new FileOutputStream( jpegFile ) );

        os.write( data );
        os.close();

        return jpegFile;
    }


    /**
     * Create a file to be used by ":&lt;" values
     * 
     * @throws Exception If the setup failed 
     */
    @BeforeEach
    public void setUp() throws Exception
    {
        data = new byte[256];

        for ( int i = 0; i < 256; i++ )
        {
            data[i] = ( byte ) i;
        }

        HJENSEN_JPEG_FILE = createFile( "hjensen", data );
    }
    
    
    @AfterEach
    public void cleanup()
    {
        FileUtils.deleteQuietly( jpegFile );
        FileUtils.deleteQuietly( tmpFolder );
    }


    @Test
    public void testLdifNull() throws LdapLdifException, IOException
    {
        String ldif = null;

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertEquals( 0, entry.size() );
        reader.close();
    }


    @Test
    public void testLdifEmpty() throws LdapLdifException, IOException
    {
        String ldif = "";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertEquals( 0, entry.size() );
        reader.close();
    }


    @Test
    public void testLdifEmptyLines() throws LdapLdifException, IOException
    {
        String ldif = "\n\n\r\r\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );
        assertNull( entry );
        reader.close();
    }


    @Test
    public void testLdifComments() throws LdapLdifException, IOException
    {
        String ldif = 
              "#Comment 1\r" 
            + "#\r" 
            + " th\n" 
            + " is is still a comment\n" 
            + "\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNull( entry );
        reader.close();
    }


    @Test
    public void testLdifVersionStart() throws LdapLdifException, IOException
    {
        String ldif = 
              "cn: app1\n" 
            + "objectClass: top\n" 
            + "objectClass: apApplication\n" 
            + "displayName:   app1   \n"
            + "dependencies:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertEquals( 1, reader.getVersion() );
        assertNotNull( entry );

        Attribute attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );
        reader.close();
    }


    /**
     * Spaces at the end of values should not be included into values.
     * 
     * @throws LdapLdifException If the test failed
     * @throws IOException If the test failed
     */
    @Test
    public void testLdifParserEndSpaces() throws LdapLdifException, IOException
    {
        String ldif = 
              "cn: app1\n" 
            + "objectClass: top\n" 
            + "objectClass: apApplication\n" 
            + "displayName:   app1   \n"
            + "dependencies:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();

        Entry entry = reader.parseEntry( ldif );
        assertNotNull( entry );

        Attribute attr = entry.get( "displayname" );
        assertTrue( attr.contains( "app1" ) );
        reader.close();
    }


    @Test
    public void testLdifParser() throws LdapLdifException, LdapInvalidAttributeValueException, IOException
    {
        String ldif = 
              "cn: app1\n" 
            + "objectClass: top\n" 
            + "objectClass: apApplication\n" 
            + "displayName: app1   \n"
            + "dependencies:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNotNull( entry );

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
        reader.close();
    }


    @Test
    public void testLdifParserMuiltiLineComments() throws LdapLdifException, IOException
    {
        String ldif = 
              "#comment\n" 
            + " still a comment\n" 
            + "cn: app1#another comment\n" 
            + "objectClass: top\n"
            + "objectClass: apApplication\n" 
            + "displayName: app1\n" 
            + "serviceType: http\n" 
            + "dependencies:\n"
            + "httpHeaders:\n" 
            + "startupOptions:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNotNull( entry );

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
        reader.close();
    }


    @Test
    public void testLdifParserMultiLineEntries() throws LdapLdifException, IOException
    {
        String ldif = 
              "#comment\n" 
            + "cn: app1#another comment\n" 
            + "objectClass: top\n" 
            + "objectClass: apAppli\n"
            + " cation\n" 
            + "displayName: app1\n" 
            + "serviceType: http\n" 
            + "dependencies:\n" 
            + "httpHeaders:\n"
            + "startupOptions:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNotNull( entry );

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
        reader.close();
    }


    @Test
    public void testLdifParserBase64() throws LdapLdifException, IOException
    {
        String ldif = 
              "#comment\n" 
            + "cn:: RW1tYW51ZWwgTMOpY2hhcm55\n" 
            + "objectClass: top\n"
            + "objectClass: apApplication\n" 
            + "displayName: app1\n" 
            + "serviceType: http\n" 
            + "dependencies:\n"
            + "httpHeaders:\n" 
            + "startupOptions:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNotNull( entry );

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
        reader.close();
    }


    @Test
    public void testLdifParserBase64MultiLine() throws LdapLdifException, IOException
    {
        String ldif = 
              "#comment\n" 
            + "cn:: RW1tYW51ZWwg\n" 
            + " TMOpY2hhcm55ICA=\n" 
            + "objectClass: top\n"
            + "objectClass: apApplication\n" 
            + "displayName: app1\n" 
            + "serviceType: http\n" 
            + "dependencies:\n"
            + "httpHeaders:\n" 
            + "startupOptions:\n" 
            + "envVars:";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

        assertNotNull( entry );

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
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample1() throws LdapLdifException, IOException
    {
        String ldif = 
              "objectclass: top\n" 
            + "objectclass: person\n" 
            + "objectclass: organizationalPerson\n"
            + "cn: Barbara Jensen\n" 
            + "cn: Barbara J Jensen\n" 
            + "cn: Babs Jensen\n" 
            + "sn: Jensen\n"
            + "uid: bjensen\n" 
            + "telephonenumber: +1 408 555 1212\n" 
            + "description: A big sailing fan.\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

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
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample2() throws LdapLdifException, IOException
    {
        String ldif = 
              "objectclass: top\n" 
            + "objectclass: person\n" 
            + "objectclass: organizationalPerson\n"
            + "cn: Barbara Jensen\n" 
            + "cn: Barbara J Jensen\n" 
            + "cn: Babs Jensen\n" 
            + "sn: Jensen\n"
            + "uid: bjensen\n" 
            + "telephonenumber: +1 408 555 1212\n"
            + "description:Babs is a big sailing fan, and travels extensively in sea\n"
            + " rch of perfect sailing conditions.\n" 
            + "title:Product Manager, Rod and Reel Division";

        LdifAttributesReader reader = new LdifAttributesReader();
        Entry entry = reader.parseEntry( ldif );

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
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample3() throws LdapLdifException, Exception
    {
        String ldif = 
              "objectclass: top\n" 
            + "objectclass: person\n" 
            + "objectclass: organizationalPerson\n"
            + "cn: Gern Jensen\n" 
            + "cn: Gern O Jensen\n" 
            + "sn: Jensen\n" 
            + "uid: gernj\n"
            + "telephonenumber: +1 408 555 1212\n"
            + "description:: V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVl\n"
            + " IGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdG\n"
            + " VyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQg\n" 
            + " b3V0IG1vcmUu";

        LdifAttributesReader reader = new LdifAttributesReader();
        Attributes attributes = reader.parseAttributes( ldif );

        javax.naming.directory.Attribute attr = attributes.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = attributes.get( "cn" );
        assertTrue( attr.contains( "Gern Jensen" ) );
        assertTrue( attr.contains( "Gern O Jensen" ) );

        attr = attributes.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = attributes.get( "uid" );
        assertTrue( attr.contains( "gernj" ) );

        attr = attributes.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = attributes.get( "description" );
        assertTrue( attr
            .contains( "What a careful reader you are!  This value is base-64-encoded because it has a control character in it (a CR).\r  By the way, you should really get out more."
                .getBytes( StandardCharsets.UTF_8 ) ) );
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample3VariousSpacing() throws LdapLdifException, Exception
    {
        String ldif = 
              "objectclass:top\n" 
            + "objectclass:   person   \n" 
            + "objectclass:organizationalPerson\n"
            + "cn:Gern Jensen\n" 
            + "cn:Gern O Jensen\n" 
            + "sn:Jensen\n" 
            + "uid:gernj\n"
            + "telephonenumber:+1 408 555 1212  \n"
            + "description::  V2hhdCBhIGNhcmVmdWwgcmVhZGVyIHlvdSBhcmUhICBUaGlzIHZhbHVl\n"
            + " IGlzIGJhc2UtNjQtZW5jb2RlZCBiZWNhdXNlIGl0IGhhcyBhIGNvbnRyb2wgY2hhcmFjdG\n"
            + " VyIGluIGl0IChhIENSKS4NICBCeSB0aGUgd2F5LCB5b3Ugc2hvdWxkIHJlYWxseSBnZXQg\n" 
            + " b3V0IG1vcmUu  ";

        LdifAttributesReader reader = new LdifAttributesReader();
        Attributes attributes = reader.parseAttributes( ldif );

        javax.naming.directory.Attribute attr = attributes.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "person" ) );
        assertTrue( attr.contains( "organizationalPerson" ) );

        attr = attributes.get( "cn" );
        assertTrue( attr.contains( "Gern Jensen" ) );
        assertTrue( attr.contains( "Gern O Jensen" ) );

        attr = attributes.get( "sn" );
        assertTrue( attr.contains( "Jensen" ) );

        attr = attributes.get( "uid" );
        assertTrue( attr.contains( "gernj" ) );

        attr = attributes.get( "telephonenumber" );
        assertTrue( attr.contains( "+1 408 555 1212" ) );

        attr = attributes.get( "description" );
        assertTrue( attr
            .contains( "What a careful reader you are!  This value is base-64-encoded because it has a control character in it (a CR).\r  By the way, you should really get out more."
                .getBytes( StandardCharsets.UTF_8 ) ) );
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample4() throws NamingException, Exception
    {
        String ldif = 
              "# dn:: ou=���������,o=Airius\n" 
            + "objectclass: top\n"
            + "objectclass: organizationalUnit\n" 
            + "ou:: 5Za25qWt6YOo\n" 
            + "# ou:: ���������\n"
            + "ou;lang-ja:: 5Za25qWt6YOo\n" 
            + "# ou;lang-ja:: ���������\n"
            + "ou;lang-ja;phonetic:: 44GI44GE44GO44KH44GG44G2\n"
            + "# ou;lang-ja:: ������������������\n" 
            + "ou;lang-en: Sales\n"
            + "description: Japanese office\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Attributes attributes = reader.parseAttributes( ldif );

        String[][] values =
            {
                { "objectclass", "top" },
                { "objectclass", "organizationalUnit" },
                { "ou", "\u55b6\u696d\u90e8" },
                { "ou;lang-ja", "\u55b6\u696d\u90e8" },
                { "ou;lang-ja;phonetic", "\u3048\u3044\u304e\u3087\u3046\u3076" }, // 3048 = ���, 3044 = ���, 304e = ���
                    // 3087 = ���, 3046 = ���, 3076 = ���
                    { "ou;lang-en", "Sales" },
                    { "description", "Japanese office" } };

        for ( int j = 0; j < values.length; j++ )
        {
            javax.naming.directory.Attribute attr = attributes.get( values[j][0] );

            if ( attr.contains( values[j][1] ) )
            {
                assertTrue( true );
            }
            else
            {
                assertTrue( attr.contains( values[j][1].getBytes( StandardCharsets.UTF_8 ) ) );
            }
        }
        
        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample5() throws NamingException, Exception
    {
        String ldif = 
              "objectclass: top\n" 
            + "objectclass: person\n" 
            + "objectclass: organizationalPerson\n"
            + "cn: Horatio Jensen\n" 
            + "cn: Horatio N Jensen\n" 
            + "sn: Jensen\n" 
            + "uid: hjensen\n"
            + "telephonenumber: +1 408 555 1212\n" 
            + "jpegphoto:< file:" 
            + HJENSEN_JPEG_FILE.getAbsolutePath() 
            + "\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Attributes attributes = reader.parseAttributes( ldif );

        String[][] values =
            {
                { "objectclass", "top" },
                { "objectclass", "person" },
                { "objectclass", "organizationalPerson" },
                { "cn", "Horatio Jensen" },
                { "cn", "Horatio N Jensen" },
                { "sn", "Jensen" },
                { "uid", "hjensen" },
                { "telephonenumber", "+1 408 555 1212" },
                { "jpegphoto", null } };

        for ( int i = 0; i < values.length; i++ )
        {
            if ( "jpegphoto".equalsIgnoreCase( values[i][0] ) )
            {
                javax.naming.directory.Attribute attr = attributes.get( values[i][0] );
                assertEquals( Strings.dumpBytes( data ), Strings.dumpBytes( ( byte[] ) attr.get() ) );
            }
            else
            {
                javax.naming.directory.Attribute attr = attributes.get( values[i][0] );

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

        reader.close();
    }


    @Test
    public void testLdifParserRFC2849Sample5WithSizeLimit() throws Exception
    {
        String ldif = 
              "objectclass: top\n" 
            + "objectclass: person\n" 
            + "objectclass: organizationalPerson\n"
            + "cn: Horatio Jensen\n"
            + "cn: Horatio N Jensen\n" 
            + "sn: Jensen\n" 
            + "uid: hjensen\n"
            + "telephonenumber: +1 408 555 1212\n" 
            + "jpegphoto:< file:" 
            + HJENSEN_JPEG_FILE.getAbsolutePath() 
            + "\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        reader.setSizeLimit( 128 );

        try
        {
            reader.parseEntry( ldif );
            fail();
        }
        catch ( LdapLdifException ne )
        {
            assertTrue( ne.getMessage().startsWith( I18n.ERR_13442_ERROR_PARSING_LDIF_BUFFER.getErrorCode() ),
                I18n.err( I18n.ERR_13442_ERROR_PARSING_LDIF_BUFFER ) );
        }

        reader.close();
    }


    @Test
    public void testLdifAttributesReaderDirServer() throws NamingException, Exception
    {
        String ldif = 
              "# -------------------------------------------------------------------\n" 
            + "#\n"
            + "#  Licensed to the Apache Software Foundation (ASF) under one\n"
            + "#  or more contributor license agreements.  See the NOTICE file\n"
            + "#  distributed with this work for additional information\n"
            + "#  regarding copyright ownership.  The ASF licenses this file\n"
            + "#  to you under the Apache License, Version 2.0 (the\n"
            + "#  \"License\"); you may not use this file except in compliance\n"
            + "#  with the License.  You may obtain a copy of the License at\n" 
            + "#  \n"
            + "#    https://www.apache.org/licenses/LICENSE-2.0\n" 
            + "#  \n"
            + "#  Unless required by applicable law or agreed to in writing,\n"
            + "#  software distributed under the License is distributed on an\n"
            + "#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n"
            + "#  KIND, either express or implied.  See the License for the\n"
            + "#  specific language governing permissions and limitations\n" 
            + "#  under the License. \n" 
            + "#  \n"
            + "#\n" 
            + "# EXAMPLE.COM is freely and reserved for testing according to this RFC:\n" 
            + "#\n"
            + "# http://www.rfc-editor.org/rfc/rfc2606.txt\n" 
            + "#\n"
            + "# -------------------------------------------------------------------\n" 
            + "\n" 
            + "objectclass: top\n"
            + "objectclass: organizationalunit\n" 
            + "ou: Users";

        LdifAttributesReader reader = new LdifAttributesReader();

        Attributes attributes = reader.parseAttributes( ldif );

        javax.naming.directory.Attribute attr = attributes.get( "objectclass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( "organizationalunit" ) );

        attr = attributes.get( "ou" );
        assertTrue( attr.contains( "Users" ) );
        reader.close();
    }


    @Test
    public void testLdifParserCommentsEmptyLines() throws NamingException, Exception
    {
        String ldif = "#\n"
            + "#  Licensed to the Apache Software Foundation (ASF) under one\n"
            + "#  or more contributor license agreements.  See the NOTICE file\n"
            + "#  distributed with this work for additional information\n"
            + "#  regarding copyright ownership.  The ASF licenses this file\n"
            + "#  to you under the Apache License, Version 2.0 (the\n"
            + "#  \"License\"); you may not use this file except in compliance\n"
            + "#  with the License.  You may obtain a copy of the License at\n"
            + "#  \n"
            + "#    https://www.apache.org/licenses/LICENSE-2.0\n"
            + "#  \n"
            + "#  Unless required by applicable law or agreed to in writing,\n"
            + "#  software distributed under the License is distributed on an\n"
            + "#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n"
            + "#  KIND, either express or implied.  See the License for the\n"
            + "#  specific language governing permissions and limitations\n"
            + "#  under the License. \n"
            + "#  \n"
            + "#\n"
            + "#\n"
            + "#   EXAMPLE.COM is freely and reserved for testing according to this RFC:\n"
            + "#\n"
            + "#   http://www.rfc-editor.org/rfc/rfc2606.txt\n"
            + "#\n"
            + "#\n"
            + "\n"
            + "#\n"
            + "# This ACI allows brouse access to the root suffix and one level below that to anyone.\n"
            + "# At this level there is nothing critical exposed.  Everything that matters is one or\n"
            + "# more levels below this.\n"
            + "#\n"
            + "\n"
            + "objectClass: top\n"
            + "objectClass: subentry\n"
            + "objectClass: accessControlSubentry\n"
            + "subtreeSpecification: { maximum 1 }\n"
            + "prescriptiveACI: { identificationTag \"browseRoot\", precedence 100, authenticationLevel none, itemOrUserFirst userFirst: { userClasses { allUsers }, userPermissions { { protectedItems {entry}, grantsAndDenials { grantReturnDN, grantBrowse } } } } }\n";

        LdifAttributesReader reader = new LdifAttributesReader();
        Attributes attributes = reader.parseAttributes( ldif );

        javax.naming.directory.Attribute attr = attributes.get( "objectClass" );
        assertTrue( attr.contains( "top" ) );
        assertTrue( attr.contains( SchemaConstants.SUBENTRY_OC ) );
        assertTrue( attr.contains( "accessControlSubentry" ) );

        attr = attributes.get( "subtreeSpecification" );
        assertTrue( attr.contains( "{ maximum 1 }" ) );

        attr = attributes.get( "prescriptiveACI" );
        assertTrue( attr
            .contains( "{ identificationTag \"browseRoot\", precedence 100, authenticationLevel none, itemOrUserFirst userFirst: { userClasses { allUsers }, userPermissions { { protectedItems {entry}, grantsAndDenials { grantReturnDN, grantBrowse } } } } }" ) );
        reader.close();
    }
}
