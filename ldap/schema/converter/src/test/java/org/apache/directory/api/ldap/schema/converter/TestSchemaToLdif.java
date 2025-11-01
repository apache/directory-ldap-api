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
package org.apache.directory.api.ldap.schema.converter;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.util.exception.ParserException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;

/**
 * Test the schema converter
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class TestSchemaToLdif
{
    private static final String HEADER =
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
            "#\n" +
            "version: 1\n" +
            "\n";


    private String transform( String name ) throws ParserException, IOException
    {
        List<Schema> schemas = new ArrayList<Schema>();
        Schema schema = new Schema();
        schema.setName( name );
        schema.setInput( getClass().getResourceAsStream( name + ".schema" ) );

        Writer out = new StringWriter( 2048 );
        schema.setOutput( out );
        schemas.add( schema );

        SchemaToLdif.transform( schemas );

        String res = out.toString();
        out.close();

        return res;
    }


    //-------------------------------------------------------------------------
    // Tests for ObjectClass
    //-------------------------------------------------------------------------
    @Test
    public void testConvertOC() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOC, ou=schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: objectClass\n" +
                "m-description: An objectClass\n" +
                "m-obsolete: TRUE\n" +
                "m-supObjectClass: top\n" +
                "m-typeObjectClass: ABSTRACT\n" +
                "m-must: attr1\n" +
                "m-must: attr2\n" +
                "m-may: attr3\n" +
                "m-may: attr4\n\n";

        assertEquals( expected, transform( "testOC" ) );
    }


    @Test
    public void testConvertOCMinimal() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMinimal, ou=s\n" +
                " chema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n\n";

        assertEquals( expected, transform( "testOCMinimal" ) );
    }


    @Test
    public void testConvertOCNoName() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCNoName, ou=sc\n" +
                " hema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-description: An objectClass\n" +
                "m-obsolete: TRUE\n" +
                "m-supObjectClass: top\n" +
                "m-typeObjectClass: ABSTRACT\n" +
                "m-must: attr1\n" +
                "m-must: attr2\n" +
                "m-may: attr3\n" +
                "m-may: attr4\n\n";

        assertEquals( expected, transform( "testOCNoName" ) );
    }


    @Test
    public void testConvertOCAbstract() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCAbstract, ou=\n" +
                " schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-typeObjectClass: ABSTRACT\n\n";

        assertEquals( expected, transform( "testOCAbstract" ) );
    }


    @Test
    public void testConvertOCAuxiliary() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCAuxiliary, ou\n" +
                " =schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-typeObjectClass: AUXILIARY\n\n";

        assertEquals( expected, transform( "testOCAuxiliary" ) );
    }


    @Test
    public void testConvertOCDesc() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCDesc, ou=sche\n" +
                " ma\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-description: An objectClass\n\n";

        assertEquals( expected, transform( "testOCDesc" ) );
    }


    @Test
    public void testConvertOCMayOne() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMayOne, ou=sc\n" +
                " hema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-may: attr1\n\n";

        assertEquals( expected, transform( "testOCMayOne" ) );
    }


    @Test
    public void testConvertOCMay2() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMay2, ou=sche\n" +
                " ma\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-may: attr1\n" +
                "m-may: attr2\n\n";

        assertEquals( expected, transform( "testOCMay2" ) );
    }


    @Test
    public void testConvertOCMayMany() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMayMany, ou=s\n" +
                " chema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-may: attr1\n" +
                "m-may: attr2\n" +
                "m-may: attr3\n\n";

        assertEquals( expected, transform( "testOCMayMany" ) );
    }


    @Test
    public void testConvertOCMustOne() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMustOne, ou=s\n" +
                " chema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-must: attr1\n\n";

        assertEquals( expected, transform( "testOCMustOne" ) );
    }


    @Test
    public void testConvertOCMust2() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMust2, ou=sch\n" +
                " ema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-must: attr1\n" +
                "m-must: attr2\n\n";

        assertEquals( expected, transform( "testOCMust2" ) );
    }


    @Test
    public void testConvertOCMustMany() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCMustMany, ou=\n" +
                " schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-must: attr1\n" +
                "m-must: attr2\n" +
                "m-must: attr3\n\n";

        assertEquals( expected, transform( "testOCMustMany" ) );
    }


    @Test
    public void testConvertOCNameOne() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCNameOne, ou=s\n" +
                " chema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: objectClass\n\n";

        assertEquals( expected, transform( "testOCNameOne" ) );
    }


    @Test
    public void testConvertOCName2() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCName2, ou=sch\n" +
                " ema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: oc\n" +
                "m-name: objectClass\n\n";

        assertEquals( expected, transform( "testOCName2" ) );
    }


    @Test
    public void testConvertOCNameMany() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCNameMany, ou=\n" +
                " schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: oc\n" +
                "m-name: objectClass\n" +
                "m-name: object\n\n";

        assertEquals( expected, transform( "testOCNameMany" ) );
    }


    @Test
    public void testConvertOCObsolete() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCObsolete, ou=\n" +
                " schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-obsolete: TRUE\n\n";

        assertEquals( expected, transform( "testOCObsolete" ) );
    }


    @Test
    public void testConvertOCSupOne() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCSupOne, ou=sc\n" +
                " hema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-supObjectClass: top\n\n";

        assertEquals( expected, transform( "testOCSupOne" ) );
    }


    @Test
    public void testConvertOCSup2() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCSup2, ou=sche\n" +
                " ma\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-supObjectClass: top\n" +
                "m-supObjectClass: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testOCSup2" ) );
    }


    @Test
    public void testConvertOCSupMany() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOCSupMany, ou=s\n" +
                " chema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-supObjectClass: top\n" +
                "m-supObjectClass: 1.3.6.1.4.1.18060.0.4.2.3.15\n" +
                "m-supObjectClass: metaTop\n\n";

        assertEquals( expected, transform( "testOCSupMany" ) );
    }
    
    
    @Disabled("Not yet supported")
    @Test
    public void testConvertOCWithOneExtention() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=objectclasses, cn=testOC, ou=schema\n" +
                "objectclass: metaObjectClass\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: objectClass\n" +
                "m-description: An objectClass\n" +
                "m-obsolete: TRUE\n" +
                "m-supObjectClass: top\n" +
                "m-typeObjectClass: ABSTRACT\n" +
                "m-must: attr1\n" +
                "m-must: attr2\n" +
                "m-may: attr3\n" +
                "m-may: attr4\n\n" +
                "m-extensionObjectClass:: T25lIGV4dGVuc2lvbiB3aXRoIFVURi04IGNoYXJzIGxpa2Ugw6k=";

        assertEquals( expected, transform( "testOCWithExtension" ) );
    }


    //-------------------------------------------------------------------------
    // Tests for Attributetype
    //-------------------------------------------------------------------------
    @Test
    public void testConvertATMinimal() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATMinimal, ou=\n" +
                " schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n\n";

        assertEquals( expected, transform( "testATMinimal" ) );
    }


    @Test
    public void testConvertATNoName() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATNoName, ou=s\n" +
                " chema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n\n";

        assertEquals( expected, transform( "testATNoName" ) );
    }


    @Test
    public void testConvertATNameOne() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATNameOne, ou=\n" +
                " schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: attribute\n\n";

        assertEquals( expected, transform( "testATNameOne" ) );
    }


    @Test
    public void testConvertATName2() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATName2, ou=sc\n" +
                " hema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: at\n" +
                "m-name: attribute\n\n";

        assertEquals( expected, transform( "testATName2" ) );
    }


    @Test
    public void testConvertATNameMany() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATNameMany, ou\n" +
                " =schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-name: at\n" +
                "m-name: attribute\n" +
                "m-name: attribute2\n\n";

        assertEquals( expected, transform( "testATNameMany" ) );
    }


    @Test
    public void testConvertATDesc() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATDesc, ou=sch\n" +
                " ema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-description: An attributeType\n\n";

        assertEquals( expected, transform( "testATDesc" ) );
    }


    @Test
    public void testConvertATDesWithEscapedChars() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATDescWithEsca\n" +
                " ped, ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-description: Some 'escaped' chars\n\n";

        assertEquals( expected, transform( "testATDescWithEscaped" ) );
    }


    @Test
    public void testConvertATObsolete() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATObsolete, ou\n" +
                " =schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-obsolete: TRUE\n\n";

        assertEquals( expected, transform( "testATObsolete" ) );
    }


    @Test
    public void testConvertATSup() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSup, ou=sche\n" +
                " ma\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-supAttributeType: anotherAttribute\n\n";

        assertEquals( expected, transform( "testATSup" ) );
    }


    @Test
    public void testConvertATSupOID() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSupOID, ou=s\n" +
                " chema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-supAttributeType: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testATSupOID" ) );
    }


    @Test
    public void testConvertATEquality() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATEquality, ou\n" +
                " =schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-equality: booleanMatch\n\n";

        assertEquals( expected, transform( "testATEquality" ) );
    }


    @Test
    public void testConvertATEqualityOID() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATEqualityOID,\n" +
                "  ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-equality: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testATEqualityOID" ) );
    }


    @Test
    public void testConvertATOrdering() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATOrdering, ou\n" +
                " =schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-ordering: booleanMatch\n\n";

        assertEquals( expected, transform( "testATOrdering" ) );
    }


    @Test
    public void testConvertATOrderingOID() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATOrderingOID,\n" +
                "  ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-ordering: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testATOrderingOID" ) );
    }


    @Test
    public void testConvertATSubstr() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSubstr, ou=s\n" +
                " chema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-substr: booleanMatch\n\n";

        assertEquals( expected, transform( "testATSubstr" ) );
    }


    @Test
    public void testConvertATSubstrOID() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSubstrOID, o\n" +
                " u=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-substr: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testATSubstrOID" ) );
    }


    @Test
    public void testConvertATSyntax() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSyntax, ou=s\n" +
                " chema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-syntax: 1.3.6.1.4.1.18060.0.4.2.3.15\n\n";

        assertEquals( expected, transform( "testATSyntax" ) );
    }


    @Test
    public void testConvertATSyntaxOidLen() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSyntaxOidLen\n" +
                " , ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-syntax: 1.3.6.1.4.1.18060.0.4.2.3.15\n" +
                "m-length: 123\n\n";

        assertEquals( expected, transform( "testATSyntaxOidLen" ) );
    }


    @Test
    public void testConvertATSingleValue() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATSingleValue,\n" +
                "  ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-singleValue: TRUE\n\n";

        assertEquals( expected, transform( "testATSingleValue" ) );
    }


    @Test
    public void testConvertATCollective() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATCollective, \n" +
                " ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-collective: TRUE\n\n";

        assertEquals( expected, transform( "testATCollective" ) );
    }


    @Test
    public void testConvertATNoUserModification() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATNoUserModifi\n" +
                " cation, ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-noUserModification: TRUE\n\n";

        assertEquals( expected, transform( "testATNoUserModification" ) );
    }


    @Test
    public void testConvertATUsageUserApp() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATUsageUserApp\n" +
                " , ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n\n";

        assertEquals( expected, transform( "testATUsageUserApp" ) );
    }


    @Test
    public void testConvertATUsageDirOp() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATUsageDirOp, \n" +
                " ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-usage: DIRECTORY_OPERATION\n\n";

        assertEquals( expected, transform( "testATUsageDirOp" ) );
    }


    @Test
    public void testConvertATUsageDistrOp() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATUsageDistrOp\n" +
                " , ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-usage: DISTRIBUTED_OPERATION\n\n";

        assertEquals( expected, transform( "testATUsageDistrOp" ) );
    }


    @Test
    public void testConvertATUsageDSAOp() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.18060.0.4.2.3.14, ou=attributetypes, cn=testATUsageDsaOp, \n" +
                " ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.18060.0.4.2.3.14\n" +
                "m-usage: DSA_OPERATION\n\n";

        assertEquals( expected, transform( "testATUsageDsaOp" ) );
    }


    @Test
    public void testConvertMozillaATWithOidLen() throws ParserException, IOException
    {
        String expected =
            HEADER +
                "dn: m-oid=1.3.6.1.4.1.13769.3.2, ou=attributetypes, cn=testMozillaATWithOidLen, \n" +
                " ou=schema\n" +
                "objectclass: metaAttributeType\n" +
                "objectclass: metaTop\n" +
                "objectclass: top\n" +
                "m-oid: 1.3.6.1.4.1.13769.3.2\n" +
                "m-name: mozillaHomeStreet2\n" +
                "m-equality: caseIgnoreMatch\n" +
                "m-substr: caseIgnoreSubstringsMatch\n" +
                "m-syntax: 1.3.6.1.4.1.1466.115.121.1.15\n" +
                "m-length: 128\n" +
                "m-singleValue: TRUE\n\n";

        assertEquals( expected, transform( "testMozillaATWithOidLen" ) );
    }
    

    @Test
    public void testConvertWrongLdif() throws ParserException, IOException
    {
        assertThrows( ParserException.class, ( ) ->
        {
            transform( "testWrongLdif" );
        } );
    }
}
