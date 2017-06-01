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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker implemented using Perl5 regular expressions to constrain
 * values.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class RegexSyntaxChecker extends SyntaxChecker
{
    /** the set of regular expressions */
    private String[] expressions;
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<RegexSyntaxChecker>
    {
        /** the set of regular expressions */
        private String[] expressions;
        
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( null );
        }


        /**
         * Add a list of regexp to be applied by this SyntaxChecker
         * 
         * @param expressions The regexp list to add
         */
        public Builder setExpressions( String[] expressions )
        {
            if ( ( expressions != null ) && ( expressions.length > 0 ) )
            {
                this.expressions = new String[expressions.length];
                System.arraycopy( expressions, 0, this.expressions, 0, expressions.length );
            }
            
            return this;
        }
        
        
        /**
         * Create a new instance of RegexSyntaxChecker
         * @return A new instance of RegexSyntaxChecker
         */
        public RegexSyntaxChecker build()
        {
            return new RegexSyntaxChecker( oid, expressions );
        }
    }

    
    /**
     * Creates a Syntax validator for a specific Syntax using Perl5 matching
     * rules for validation.
     * 
     * @param oid the oid of the Syntax values checked
     * @param matchExprArray the array of matching expressions
     */
    private RegexSyntaxChecker( String oid, String[] matchExprArray )
    {
        super( oid );

        this.expressions = matchExprArray;
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
        String str;

        if ( value instanceof String )
        {
            str = ( String ) value;

            for ( String regexp : expressions )
            {
                if ( !str.matches( regexp ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
        }

        return true;
    }


    /**
     * Get the list of regexp stored into this SyntaxChecker
     * 
     * @return AN array containing all the stored regexp
     */
    public String[] getExpressions()
    {
        if ( expressions == null )
        {
            return Strings.EMPTY_STRING_ARRAY;
        }
        
        String[] exprs = new String[expressions.length];
        System.arraycopy( expressions, 0, exprs, 0, expressions.length );
        
        return exprs;
    }
}
