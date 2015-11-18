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
package org.apache.directory.api.osgi;


import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.schema.converter.Schema;
import org.apache.directory.api.ldap.schema.converter.SchemaToLdif;
import org.apache.directory.api.util.Strings;


public class ApiLdapSchemaConverterOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.schema.converter";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        List<Schema> schemas = new ArrayList<Schema>();

        Schema schema = new Schema();
        schema.setName( "foo" );
        schema.setInput( new ByteArrayInputStream(
            Strings.getBytesUtf8( "attributetype ( 1.3.6.1.4.1.18060.0.4.2.3.14 NAME ( 'at' 'attribute' ) )" ) ) );

        Writer out = new StringWriter( 2048 );
        schema.setOutput( out );
        schemas.add( schema );

        SchemaToLdif.transform( schemas );
    }

}
