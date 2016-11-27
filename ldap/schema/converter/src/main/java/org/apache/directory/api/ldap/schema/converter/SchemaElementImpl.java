/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
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


import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifUtils;
import org.apache.directory.api.util.Strings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * An abstract SchemaElement implementation. It contains shared
 * elements from AttributeType and ObjectClass, like obsolete, oid, 
 * description, names and extensions (not implemented)
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class SchemaElementImpl implements SchemaElement
{
    /** The schema element oid */
    protected String oid;

    /** The schema element description */
    protected String description;

    /** The list of names for this schemaElements */
    protected List<String> names = new ArrayList<>();

    /** The obsolete flag */
    protected boolean obsolete = false;

    /** The optional list of extensions */
    protected Map<String, List<String>> extensions = new HashMap<>();


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isObsolete()
    {
        return obsolete;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setObsolete( boolean obsolete )
    {
        this.obsolete = obsolete;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return oid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getDescription()
    {
        return description;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDescription( String description )
    {
        this.description = description;
    }


    /**
     * @see SchemaElement#getNames()
     */
    @Override
    public List<String> getNames()
    {
        return names;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setNames( List<String> names )
    {
        this.names = names;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getExtension( String key )
    {
        return extensions.get( key );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, List<String>> getExtensions()
    {
        return extensions;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setExtensions( Map<String, List<String>> extensions )
    {
        this.extensions = extensions;
    }


    /**
     * @return The OID as a Ldif line
     */
    private String oidToLdif()
    {
        return "m-oid: " + oid + '\n';
    }


    /**
     * @return the Names as Ldif lines
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the conversion goes wrong
     */
    private String nameToLdif() throws LdapException
    {
        if ( names.isEmpty() )
        {
            return "";
        }
        else
        {
            Entry entry = new DefaultEntry();
            Attribute attribute = new DefaultAttribute( "m-name" );

            for ( String name : names )
            {
                attribute.add( name );
            }

            entry.put( attribute );

            return LdifUtils.convertAttributesToLdif( entry );
        }
    }


    /**
     * @return The description as a ldif line
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the conversion goes wrong
     */
    private String descToLdif() throws LdapException
    {
        if ( Strings.isEmpty( description ) )
        {
            return "";
        }
        else
        {
            Entry entry = new DefaultEntry();
            Attribute attribute = new DefaultAttribute( "m-description", description );

            entry.put( attribute );

            return LdifUtils.convertAttributesToLdif( entry );
        }
    }


    /**
     * Transform a Schema Element to a LDIF String
     *
     * @param schemaName The schema element to transform
     * @return The Schema Element as a ldif String
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the conversion goes wrong
     */
    public abstract String dnToLdif( String schemaName ) throws LdapException;


    /**
     * Return the extensions formated as Ldif lines
     *
     * @param id The attributeId : can be m-objectClassExtension or
     * m-attributeTypeExtension
     * @return The extensions formated as ldif lines
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the conversion goes wrong
     */
    protected String extensionsToLdif( String id ) throws LdapException
    {
        StringBuilder sb = new StringBuilder();

        Entry entry = new DefaultEntry();
        Attribute attribute = new DefaultAttribute( id );

        for ( String extension : extensions.keySet() )
        {
            attribute.add( extension );
        }

        sb.append( LdifUtils.convertAttributesToLdif( entry ) );

        return sb.toString();
    }


    /**
     * Transform a Schema to a LDIF formated String
     *
     * @param schemaName The schema to transform
     * @param type The ObjectClass type
     * @return A LDIF String representing the schema
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the transformation can't be done
     */
    protected String schemaToLdif( String schemaName, String type ) throws LdapException
    {
        StringBuilder sb = new StringBuilder();

        // The Dn
        sb.append( dnToLdif( schemaName ) );

        // ObjectClasses
        sb.append( "objectclass: " ).append( type ).append( '\n' );
        sb.append( "objectclass: metaTop\n" );
        sb.append( "objectclass: top\n" );

        // The oid
        sb.append( oidToLdif() );

        // The name
        sb.append( nameToLdif() );

        // The desc
        sb.append( descToLdif() );

        // The obsolete flag, only if "true"
        if ( obsolete )
        {
            sb.append( "m-obsolete: TRUE\n" );
        }

        return sb.toString();
    }
}
