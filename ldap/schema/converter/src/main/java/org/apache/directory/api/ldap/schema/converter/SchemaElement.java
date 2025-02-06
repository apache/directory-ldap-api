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


import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * An interface defining the methods to be implemented by the SchemaElement 
 * classes
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SchemaElement
{
    /**
     * Tells if the attributeType is obsolete
     * 
     * @return true if the schema element is obsolete, folse otherwise
     */
    boolean isObsolete();


    /**
     * Set the obsolete flag
     * 
     * @param isObsolete The value to be set
     */
    void setObsolete( boolean isObsolete );


    /**
     * Get the Schema Element OID
     * 
     * @return the schema element's OID
     */
    String getOid();


    /**
     * Get the dschema element description
     * 
     * @return Return the schema element description
     */
    String getDescription();


    /**
     * Set the schema element's description
     * 
     * @param description The schema element's description
     */
    void setDescription( String description );


    /**
     * Get the list of possible names
     * 
     * @return The list of names for the schemaElement
     */
    List<String> getNames();


    /**
     * Set a list of names for a schemaElement
     * 
     * @param names The list of names of this schemaElement
     */
    void setNames( List<String> names );


    /**
     * Get the list of extensions
     * 
     * @return The list of extensions for the schemaElement
     */
    Map<String, List<String>> getExtensions();


    /**
     * Get the extension associated to a key
     * 
     * @param key the Extension key
     * @return The list of a values for a given extension
     */
    List<String> getExtension( String key );


    /**
     * Set a list of extensions for a schemaElement
     * 
     * @param extensions The list of extensions of this schemaElement
     */
    void setExtensions( Map<String, List<String>> extensions );


    /**
     * Generate a String representation of this schemaElement, formated
     * as a ldif string 
     * 
     * @param schemaName The schema from which is extracted this schemaElement
     * @return A string representing the schemaElement as a Ldif formated  String 
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If any error occurs.
     */
    String toLdif( String schemaName ) throws LdapException;
}
