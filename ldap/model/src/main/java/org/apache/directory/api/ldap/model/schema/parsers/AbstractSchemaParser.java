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
package org.apache.directory.api.ldap.model.schema.parsers;


import java.text.ParseException;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.MetaSchemaConstants;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.OpenLdapObjectIdentifierMacro;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Base class of all schema parsers.
 * 
 * @param <T> The type of SchemaObject
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractSchemaParser<T extends SchemaObject>
{
    /** The LoggerFactory used by this class */
    protected static final Logger LOG = LoggerFactory.getLogger( AbstractSchemaParser.class );

    /** The fast schemaObject parser */
    protected OpenLdapSchemaParser fastParser;

    /** error code used when schema descritpion is null */
    private I18n errorCodeOnNull;

    /**
     * Instantiates a new abstract schema parser.
     * 
     * @param schemaObjectType The Schema object type
     * @param errorCodeOnNull error code used when schema element is null
     * @param errorCodeOnParseExceptionWithPosition error code used on parse error when position is known
     * @param errorCodeOnParseException error code used on parse error when position is unknown
     */
    protected AbstractSchemaParser( Class<T> schemaObjectType, I18n errorCodeOnNull,
        I18n errorCodeOnParseExceptionWithPosition,
        I18n errorCodeOnParseException )
    {
        this.errorCodeOnNull = errorCodeOnNull;
        fastParser = new OpenLdapSchemaParser();
    }



    /**
     * Sets the quirks mode. 
     * 
     * If enabled the parser accepts non-numeric OIDs and some 
     * special characters in descriptions.
     * 
     * @param enabled the new quirks mode
     */
    public void setQuirksMode( boolean enabled )
    {
        fastParser.setQuirksMode( enabled );
    }


    /**
     * Checks if quirks mode is enabled.
     * 
     * @return true, if is quirks mode is enabled
     */
    public boolean isQuirksMode()
    {
        return fastParser.isQuirksMode();
    }


    /**
     * Parse a SchemaObject description and returns back an instance of SchemaObject.
     * 
     * @param schemaDescription The SchemaObject description
     * @return A SchemaObject instance
     * @throws ParseException If the parsing failed
     */
    public abstract T parse( String schemaDescription ) throws ParseException;


    /**
     * Update the schemaName for the given SchemaObject, accordingly to the X-SCHEMA parameter. If
     * not present, default to 'other'
     *
     * @param schemaObject the schema object where the name should be updated
     */
    protected void updateSchemaName( SchemaObject schemaObject )
    {
        // Update the Schema if we have the X-SCHEMA extension
        List<String> schemaExtension = schemaObject.getExtension( MetaSchemaConstants.X_SCHEMA_AT );

        if ( schemaExtension != null )
        {
            String schemaName = schemaExtension.get( 0 );

            if ( Strings.isEmpty( schemaName ) )
            {
                schemaObject.setSchemaName( MetaSchemaConstants.SCHEMA_OTHER );
            }
            else
            {
                schemaObject.setSchemaName( schemaName );
            }
        }
        else
        {
            schemaObject.setSchemaName( MetaSchemaConstants.SCHEMA_OTHER );
        }
    }
    
    
    /**
     * Get the defined macros.
     * 
     * @return The map of defined macros
     */
    public Map<String, OpenLdapObjectIdentifierMacro> getObjectIdentifiers()
    {
        return fastParser.getObjectIdentifierMacros();
    }
}
