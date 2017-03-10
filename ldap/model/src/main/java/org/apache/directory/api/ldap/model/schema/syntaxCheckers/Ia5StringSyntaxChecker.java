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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A SyntaxChecker which verifies that a value is a IA5 String according to RFC 4517.
 * <p>
 * From RFC 4517 :
 * <pre>
 * IA5String          = *(%x00-7F)
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class Ia5StringSyntaxChecker extends SyntaxChecker
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( Ia5StringSyntaxChecker.class );
    
    /**
     * A static instance of Ia5StringSyntaxChecker
     */
    public static final Ia5StringSyntaxChecker INSTANCE = new Ia5StringSyntaxChecker();

    /**
     * Creates a new instance of Ia5StringSyntaxChecker.
     */
    public Ia5StringSyntaxChecker()
    {
        super( SchemaConstants.IA5_STRING_SYNTAX );
    }


    /**
     * Creates a new instance of a child with a given OID.
     * 
     * @param oid the child's oid
     */
    protected Ia5StringSyntaxChecker( String oid )
    {
        super( oid );
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
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            return true;
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

        boolean result = Strings.isIA5String( strValue );

        if ( result )
        {
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
        }
        else
        {
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
        }

        return result;
    }
}
