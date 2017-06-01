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
package org.apache.directory.api.ldap.model.schema.syntaxCheckers;


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.schema.parsers.NameFormDescriptionSchemaParser;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value follows the
 * name descripton syntax according to RFC 4512, par 4.2.7.2:
 * 
 * <pre>
 * NameFormDescription = LPAREN WSP
 *    numericoid                 ; object identifier
 *    [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
 *    [ SP "DESC" SP qdstring ]  ; description
 *    [ SP "OBSOLETE" ]          ; not active
 *    SP "OC" SP oid             ; structural object class
 *    SP "MUST" SP oids          ; attribute types
 *    [ SP "MAY" SP oids ]       ; attribute types
 *    extensions WSP RPAREN      ; extensions
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class NameFormDescriptionSyntaxChecker extends SyntaxChecker
{
    /** The schema parser used to parse the DITContentRuleDescription Syntax */
    private transient NameFormDescriptionSchemaParser schemaParser = new NameFormDescriptionSchemaParser();
    
    /**
     * A static instance of NameFormDescriptionSyntaxChecker
     */
    public static final NameFormDescriptionSyntaxChecker INSTANCE = 
        new NameFormDescriptionSyntaxChecker( SchemaConstants.NAME_FORM_DESCRIPTION_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<NameFormDescriptionSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.NAME_FORM_DESCRIPTION_SYNTAX );
        }
        
        
        /**
         * Create a new instance of NameFormDescriptionSyntaxChecker
         * @return A new instance of NameFormDescriptionSyntaxChecker
         */
        @Override
        public NameFormDescriptionSyntaxChecker build()
        {
            return new NameFormDescriptionSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of DITContentRuleDescriptionSyntaxChecker.
     *
     * @param oid The OID to use for this SyntaxChecker
     */
    private NameFormDescriptionSyntaxChecker( String oid )
    {
        super( oid );
    }

    
    /**
     * @return An instance of the Builder for this class
     */
    public static Builder builder()
    {
        return new Builder();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValidSyntax( Object value )
    {
        String strValue;

        if ( value == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            }
            
            return false;
        }

        if ( value instanceof String )
        {
            strValue = ( String ) value;
        }
        else if ( value instanceof byte[] )
        {
            strValue = Strings.utf8ToString( ( byte[] ) value );
        }
        else
        {
            strValue = value.toString();
        }

        try
        {
            schemaParser.parseNameFormDescription( strValue );
            
            return true;
        }
        catch ( ParseException pe )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
    }
}
