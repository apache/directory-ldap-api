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


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.ldif.LdifUtils;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.ObjectClassTypeEnum;


/**
 * A bean used to encapsulate the literal String values of an ObjectClass
 * definition found within an OpenLDAP schema configuration file.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ObjectClassHolder extends SchemaElementImpl
{
    /** The list of superiors */
    private List<String> superiors = new ArrayList<>();

    /** The list of mandatory attributes */
    private List<String> must = new ArrayList<>();

    /** The list of optional attributes */
    private List<String> may = new ArrayList<>();

    /** The ObjectClass type */
    private ObjectClassTypeEnum classType = ObjectClassTypeEnum.STRUCTURAL;


    /**
     * Create an instance of ObjectClass element
     * 
     * @param oid the OjectClass OID
     */
    public ObjectClassHolder( String oid )
    {
        this.oid = oid;
    }


    /**
     * Get the list of superior for this objectClass
     * @return A list of all inherited objectClasses 
     */
    public List<String> getSuperiors()
    {
        return superiors;
    }


    /**
     * Set the list of inherited objectClasses
     * @param superiors The list of inherited objectClasses
     */
    public void setSuperiors( List<String> superiors )
    {
        this.superiors = superiors;
    }


    /**
     * @return The list of mandatory attributes
     */
    public List<String> getMust()
    {
        return must;
    }


    /**
     * Set the list of mandatory attributes
     * @param must The list of mandatory attributes
     */
    public void setMust( List<String> must )
    {
        this.must = must;
    }


    /**
     * @return The list of optional attributes
     */
    public List<String> getMay()
    {
        return may;
    }


    /**
     * Set the list of optional attributes
     * @param may The list of optional attributes
     */
    public void setMay( List<String> may )
    {
        this.may = may;
    }


    /**
     * @return The objectClass type
     */
    public ObjectClassTypeEnum getClassType()
    {
        return classType;
    }


    /**
     * Set the objectClass type. 
     * @param classType The objectClass type. 
     */
    public void setClassType( ObjectClassTypeEnum classType )
    {
        this.classType = classType;
    }


    /**
     * Convert this objectClass to a Ldif string
     * 
     * @param schemaName The name of the schema file containing this objectClass
     * @return A ldif formatted string
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If something went wrong
     */
    @Override
    public String toLdif( String schemaName ) throws LdapException
    {
        StringBuilder sb = new StringBuilder();

        sb.append( schemaToLdif( schemaName, "metaObjectClass" ) );

        // The superiors
        if ( !superiors.isEmpty() )
        {
            for ( String superior : superiors )
            {
                sb.append( "m-supObjectClass: " ).append( superior ).append( '\n' );
            }
        }

        // The kind of class
        if ( classType != ObjectClassTypeEnum.STRUCTURAL )
        {
            sb.append( "m-typeObjectClass: " ).append( classType ).append( '\n' );
        }

        // The 'must'
        if ( !must.isEmpty() )
        {
            for ( String attr : must )
            {
                sb.append( "m-must: " ).append( attr ).append( '\n' );
            }
        }

        // The 'may'
        if ( !may.isEmpty() )
        {
            for ( String attr : may )
            {
                sb.append( "m-may: " ).append( attr ).append( '\n' );
            }
        }

        // The extensions
        if ( !extensions.isEmpty() )
        {
            extensionsToLdif( "m-extensionObjectClass" );
        }

        return sb.toString();
    }


    /**
     * @return a String representing this ObjectClass.
     */
    @Override
    public String toString()
    {
        return getOid();
    }


    /**
     * Transform a schema name to a Dn pointing to the correct position in the DIT
     * 
     * @param schemaName The schema name
     * @return the Dn associated with this schema in the DIT
     */
    @Override
    public String dnToLdif( String schemaName ) throws LdapException
    {
        StringBuilder sb = new StringBuilder();

        String dn = "m-oid=" + oid + ", " + SchemaConstants.OBJECT_CLASSES_PATH + ", cn="
            + Rdn.escapeValue( schemaName ) + ", ou=schema";

        // First dump the Dn only
        Entry entry = new DefaultEntry( dn );
        sb.append( LdifUtils.convertToLdif( entry ) );

        return sb.toString();
    }
}
