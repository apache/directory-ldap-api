/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.ldap.client.api.search;

import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.AttributeUtils;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstract class used as a base for all the Filter implementations
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
/* No qualifier*/abstract class AbstractFilter implements Filter
{
    /** A logger for this class and its descendant */
    protected static final Logger LOGGER = LoggerFactory.getLogger( Filter.class );
    
    /**
     * {@inheritDoc}
     */
    @Override
    public StringBuilder build()
    {
        return build( new StringBuilder() );
    }
    


    /**
     * Checks that a matching rule operand is a valid matching rule name
     * (a keystring) or a numeric OID, as it is concatenated unescaped into
     * the produced filter. A null or empty matching rule is accepted, as it
     * simply means 'not set'.
     *
     * @param matchingRule The matching rule to check
     * @return The checked matching rule
     * @throws IllegalArgumentException If the matching rule is not valid
     */
    /* No qualifier*/static String checkMatchingRule( String matchingRule )
    {
        if ( ( matchingRule == null ) || matchingRule.isEmpty() )
        {
            return matchingRule;
        }

        if ( isKeyString( matchingRule ) )
        {
            return matchingRule;
        }
        else
        {
            try
            {
                AttributeUtils.parseOID( matchingRule, 0 );
            }
            catch ( ParseException pe )
            {
                throw new IllegalArgumentException( I18n.err(  I18n.ERR_04182_INVALID_MATCHING_RULE, matchingRule ) );
            }

            return matchingRule;
        }
    }


    /**
     * Checks a RFC 4512 keystrTing : leadkeychar *keychar
     *
     * @param str The string to check
     * @return true if the string is a valid keystring
     */
    private static boolean isKeyString( String str )
    {
        if ( str.isEmpty() || !Strings.isAlpha( str.charAt( 0 ) ) )
        {
            return false;
        }

        for ( int i = 1; i < str.length(); i++ )
        {
            char c = str.charAt( i );

            if ( !Strings.isAlpha( c ) && !Strings.isDigit( c ) && ( c != '-' ) )
            {
                return false;
            }
        }

        return true;
    }
}
