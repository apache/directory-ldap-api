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
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is an OtherMailbox according to 
 * RFC 4517 :
 * <pre>
 * OtherMailbox = mailbox-type DOLLAR mailbox
 * mailbox-type = PrintableString
 * mailbox      = IA5String
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class OtherMailboxSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of OtherMailboxSyntaxChecker
     */
    public static final OtherMailboxSyntaxChecker INSTANCE = 
        new OtherMailboxSyntaxChecker( SchemaConstants.OTHER_MAILBOX_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<OtherMailboxSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.OTHER_MAILBOX_SYNTAX );
        }
        
        
        /**
         * Create a new instance of OtherMailboxSyntaxChecker
         * @return A new instance of OtherMailboxSyntaxChecker
         */
        @Override
        public OtherMailboxSyntaxChecker build()
        {
            return new OtherMailboxSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of OtherMailboxSyntaxChecker.
     */
    private OtherMailboxSyntaxChecker( String oid )
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

        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Search for the '$' separator
        int dollar = strValue.indexOf( '$' );

        if ( dollar == -1 )
        {
            // No '$' => error
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String mailboxType = strValue.substring( 0, dollar );

        String mailbox = ( dollar < strValue.length() - 1 )
            ? strValue.substring( dollar + 1 ) : "";

        // The mailbox should not contains a '$'
        if ( mailbox.indexOf( '$' ) != -1 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check that the mailboxType is a PrintableString
        if ( !Strings.isPrintableString( mailboxType ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check that the mailbox is an IA5String
        boolean result = Strings.isIA5String( mailbox );

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
