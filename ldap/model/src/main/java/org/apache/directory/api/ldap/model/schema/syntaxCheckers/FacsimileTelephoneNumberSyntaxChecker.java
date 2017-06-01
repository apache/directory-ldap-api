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


import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a facsimile TelephoneNumber according 
 * to ITU recommendation E.123 for the Telephone number part, and from RFC 4517, par. 
 * 3.3.11 :
 * 
 * <pre>
 * fax-number       = telephone-number *( DOLLAR fax-parameter )
 * telephone-number = PrintableString
 * fax-parameter    = "twoDimensional" |
 *                    "fineResolution" |
 *                    "unlimitedLength" |
 *                    "b4Length" |
 *                    "a3Width" |
 *                    "b4Width" |
 *                    "uncompressed"
 * </pre>
 * 
 * If needed, and to allow more syntaxes, a list of regexps has been added
 * which can be initialized to other values
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class FacsimileTelephoneNumberSyntaxChecker extends SyntaxChecker
{
    /** The default pattern used to check a TelephoneNumber */
    private static final String DEFAULT_REGEXP = "^ *[+]? *((\\([0-9- ,;/#*]+\\))|[0-9- ,;/#*]+)+$";
    
    /** The default pattern */
    private final String defaultRegexp;

    /** The compiled default pattern */
    private Pattern defaultPattern;
    
    /** Fax parameters possible values */
    private static final String TWO_DIMENSIONAL = "twoDimensional";
    private static final String FINE_RESOLUTION = "fineResolution";
    private static final String UNLIMITED_LENGTH = "unlimitedLength";
    private static final String B4_LENGTH = "b4Length";
    private static final String A3_LENGTH = "a3Width";
    private static final String B4_WIDTH = "b4Width";
    private static final String UNCOMPRESSED = "uncompressed";

    /** A set which contains all the possible fax parameters values */
    private static Set<String> faxParameters = new HashSet<>();

    /** Initialization of the fax parameters set of values */
    static
    {
        faxParameters.add( Strings.toLowerCaseAscii( TWO_DIMENSIONAL ) );
        faxParameters.add( Strings.toLowerCaseAscii( FINE_RESOLUTION ) );
        faxParameters.add( Strings.toLowerCaseAscii( UNLIMITED_LENGTH ) );
        faxParameters.add( Strings.toLowerCaseAscii( B4_LENGTH ) );
        faxParameters.add( Strings.toLowerCaseAscii( A3_LENGTH ) );
        faxParameters.add( Strings.toLowerCaseAscii( B4_WIDTH ) );
        faxParameters.add( Strings.toLowerCaseAscii( UNCOMPRESSED ) );
    }
    
    /**
     * A static instance of FacsimileTelephoneNumberSyntaxChecker
     */
    public static final FacsimileTelephoneNumberSyntaxChecker INSTANCE = 
        new FacsimileTelephoneNumberSyntaxChecker( SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<FacsimileTelephoneNumberSyntaxChecker>
    {
        /** The compiled default pattern */
        private String defaultRegexp;

        /** The compiled default pattern */
        private Pattern defaultPattern;

        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_SYNTAX );
            setDefaultRegexp( DEFAULT_REGEXP );
        }


        /**
         * Create a new instance of FacsimileTelephoneNumberSyntaxChecker
         * @return A new instance of FacsimileTelephoneNumberSyntaxChecker
         */
        @Override
        public FacsimileTelephoneNumberSyntaxChecker build()
        {
            return new FacsimileTelephoneNumberSyntaxChecker( oid, defaultRegexp, defaultPattern );
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
     * Creates a new instance of TelephoneNumberSyntaxChecker.
     */
    private FacsimileTelephoneNumberSyntaxChecker( String oid )
    {
        this( oid, DEFAULT_REGEXP, Pattern.compile( DEFAULT_REGEXP ) );
    }


    /**
     * Creates a new instance of TelephoneNumberSyntaxChecker.
     */
    private FacsimileTelephoneNumberSyntaxChecker( String oid, String defaultRegexp, Pattern defaultPattern )
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
        if ( defaultRegexp == null )
        {
            return DEFAULT_REGEXP;
        }
        else
        {
            return defaultRegexp;
        }
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

        // The facsimile telephone number might be composed
        // of two parts separated by a '$'.
        int dollarPos = strValue.indexOf( '$' );

        if ( dollarPos == -1 )
        {
            // We have no fax-parameter : check the Telephone number
            boolean result = defaultPattern.matcher( strValue ).matches();

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

        // First check the telephone number if the '$' is not at the first position
        if ( dollarPos > 0 )
        {
            boolean result = defaultPattern.matcher( strValue.substring( 0, dollarPos - 1 ) ).matches();

            if ( LOG.isDebugEnabled() )
            {
                if ( result )
                {
                    LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
                }
                else
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    
                    return false;
                }
            }

            // Now, try to validate the fax-parameters : we may
            // have more than one, so we will store the seen params
            // in a set to check that we don't have the same param twice
            Set<String> paramsSeen = new HashSet<>();

            while ( dollarPos > 0 )
            {
                String faxParam;
                int newDollar = strValue.indexOf( '$', dollarPos + 1 );

                if ( newDollar == -1 )
                {
                    faxParam = strValue.substring( dollarPos + 1 );
                }
                else
                {
                    faxParam = strValue.substring( dollarPos + 1, newDollar );
                }

                if ( faxParam.length() == 0 )
                {
                    // Not allowed
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                // Relax a little bit the syntax by lowercasing the param
                faxParam = Strings.toLowerCaseAscii( faxParam );

                if ( !faxParameters.contains( faxParam ) || paramsSeen.contains( faxParam ) )
                {
                    // This parameter is not in the possible set
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }
                else
                {
                    // It's a correct param, let's add it to the seen 
                    // params.
                    paramsSeen.add( faxParam );
                }

                dollarPos = newDollar;
            }

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }

        // We must have a valid telephone number !
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
        }
        
        return false;
    }
}
