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


import org.apache.directory.api.ldap.model.entry.AttributeUtils;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.parsers.ObjectClassDescriptionSchemaParser;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.url.LdapUrl;


public class ApiLdapModelOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.model";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        new Dn( "dc=example,dc=com" ); // uses FastDnParser
        new Dn( "cn=a+sn=b,dc=example,dc=com" ); // uses ComplexDnparser (antlr based)
        new StringValue( "foo" );
        new DefaultAttribute( "cn" );
        new DefaultEntry();

        AttributeUtils.toJndiAttribute( new DefaultAttribute( "cn" ) );
        
        new BindRequestImpl();

        new EqualityNode<String>( "cn", new StringValue( "foo" ) );

        new LdapUrl( "ldap://ldap.example.com:10389/dc=example,dc=com?objectclass" );

        new ObjectClassDescriptionSchemaParser()
            .parse( "( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )" );
        
        SchemaObject schemaObject = new LdapSyntax( "1.2.3" );
        new Registries().getGlobalOidRegistry().register( schemaObject );
        new Registries().getLoadedSchemas();
    }

}
