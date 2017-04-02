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


import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a TelephoneNumber according to ITU
 * recommendation E.123 (which is quite vague ...).
 * <p>
 * A valid Telephone number respects more or less this syntax :
 * 
 * <pre>
 * " *[+]? *((\([0-9- ,;/#*]+\))|[0-9- ,;/#*]+)+"
 * </pre>
 * 
 * If needed, and to allow more syntaxes, a list of regexps has been added
 * which can be initialized to other values
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class TelephoneNumberSyntaxChecker extends SyntaxChecker
{
    /** The default pattern used to check a TelephoneNumber */
    private static final String DEFAULT_REGEXP = "^ *[+]? *((\\([0-9- ,;/#*]+\\))|[0-9- ,;/#*]+)+$";
    
    /** The default pattern */
    private final String defaultRegexp;

    /** The compiled default pattern */
    private final Pattern defaultPattern;

    /**
     * A static instance of TelephoneNumberSyntaxChecker
     */
    public static final TelephoneNumberSyntaxChecker INSTANCE = 
        new TelephoneNumberSyntaxChecker( SchemaConstants.TELEPHONE_NUMBER_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<TelephoneNumberSyntaxChecker>
    {
        /** The default pattern */
        private String defaultRegexp;

        /** The compiled default pattern */
        private Pattern defaultPattern;

        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.TELEPHONE_NUMBER_SYNTAX );
            setDefaultRegexp( DEFAULT_REGEXP );
        }
        
        
        /**
         * Create a new instance of TelephoneNumberSyntaxChecker
         * @return A new instance of TelephoneNumberSyntaxChecker
         */
        @Override
        public TelephoneNumberSyntaxChecker build()
        {
            return new TelephoneNumberSyntaxChecker( oid, defaultRegexp, defaultPattern );
        }


        /**
         * Set the default regular expression for the Telephone number
         * 
         * @param regexp the default regular expression.
         */
        public Builder setDefaultRegexp( String regexp )
        {
            defaultRegexp = regexp;
            
            try
            {
                defaultPattern = Pattern.compile( regexp );
            }
            catch ( PatternSyntaxException pse )
            {
                // Roll back to the default pattern
                defaultPattern = Pattern.compile( DEFAULT_REGEXP );
            }

            return this;
        }
    }

    
    /**
     * Creates a new instance of a child of this class, with an OID.
     * 
     * @param oid the child's OID
     */
    private TelephoneNumberSyntaxChecker( String oid )
    {
        this( oid, DEFAULT_REGEXP, Pattern.compile( DEFAULT_REGEXP ) );
    }

    
    /**
     * Creates a new instance of a child of this class, with an OID.
     * 
     * @param oid the child's OID
     * @param defaultRegexp The regexp to use
     * @param defaultPattern The compiled version of the regexp
     */
    private TelephoneNumberSyntaxChecker( String oid, String defaultRegexp, Pattern defaultPattern )
    {
        super( oid );

        this.defaultPattern = defaultPattern;
        this.defaultRegexp = defaultRegexp;
    }

    
    /**
     * @return An instance of the Builder for this class
     */
    public static Builder builder()
    {
        return new Builder();
    }


    /**
     * Get the default regexp (either the original one, or the one that has been set)
     * 
     * @return The default regexp
     */
    public String getRegexp()
    {
        return defaultRegexp;
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

        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // We will use a regexp to check the TelephoneNumber.
        boolean result;
        
        // Not sure this is 100% necessary...
        synchronized ( defaultPattern )
        {
            result = defaultPattern.matcher( strValue ).matches();
        }

        if ( LOG.isDebugEnabled() )
        {
            if ( result )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            else
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
        }

        return result;
    }
}
