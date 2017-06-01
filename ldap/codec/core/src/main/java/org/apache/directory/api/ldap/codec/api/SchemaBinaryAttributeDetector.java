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
package org.apache.directory.api.ldap.codec.api;

import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;

/**
 * An implementation of the BinaryAttributeDetector interface. It's not
 * schema aware, so it only uses the list of binary Attributes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SchemaBinaryAttributeDetector implements BinaryAttributeDetector
{
    /** The schemaManager to use */
    private SchemaManager schemaManager;
    
    
    protected SchemaBinaryAttributeDetector()
    {
    }
    
    
    /**
     * Create an instance of SchemaBinaryAttributeDetector.
     * 
     * @param schemaManager The SchemaManager to use
     */
    public SchemaBinaryAttributeDetector( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }

    /**
     * @param schemaManager the schemaManager to set
     */
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBinary( String attributeId )
    {
        String attrId = Strings.toLowerCaseAscii( attributeId );

        if ( attrId.endsWith( ";binary" ) )
        {
            return true;
        }

        if ( schemaManager != null )
        {
            AttributeType attributeType =  schemaManager.getAttributeType( attrId );
            
            if ( attributeType == null )
            {
                return false;
            }
            
            LdapSyntax ldapSyntax = attributeType.getSyntax();
            
            return ( ldapSyntax != null ) && !ldapSyntax.isHumanReadable();
        }

        return false;
    }
}
