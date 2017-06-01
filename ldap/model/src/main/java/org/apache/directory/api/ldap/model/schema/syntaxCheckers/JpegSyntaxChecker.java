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


/**
 * A SyntaxChecker which verifies that a value is a Jpeg according to RFC 4517.
 * <p>
 * The JFIF (Jpeg File Interchange Format) specify that a jpeg image starts with
 * the following bytes :
 * <pre>
 * 0xFF 0xD8 (SOI, Start Of Image)
 * 0xFF 0xE0 (App0 for JFIF) or 0xDD 0xE1 (App1 for Exif)
 * 0xNN 0xNN (Header length)
 * "JFIF\0" (JFIF string with an ending \0)
 * some other bytes which are related to the image.
 * <pre>
 * 
 * We will check for those 11 bytes, except the length.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class JpegSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of JpegSyntaxChecker
     */
    public static final JpegSyntaxChecker INSTANCE = new JpegSyntaxChecker( SchemaConstants.JPEG_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<JpegSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.JPEG_SYNTAX );
        }
        
        
        /**
         * Create a new instance of JpegSyntaxChecker
         * @return A new instance of JpegSyntaxChecker
         */
        @Override
        public JpegSyntaxChecker build()
        {
            return new JpegSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of JpegSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private JpegSyntaxChecker( String oid )
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
        if ( value == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            }
            
            return false;
        }

        // The value must be a byte array
        if ( !( value instanceof byte[] ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        byte[] bytes = ( byte[] ) value;

        // The header must be at least 11 bytes long
        if ( bytes.length < 11 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // SOI or APP0 or APP1 format
        if ( ( bytes[0] == ( byte ) 0x00FF )
            && ( bytes[1] == ( byte ) 0x00D8 )
            && ( bytes[2] == ( byte ) 0x00FF ) )
        {
            // JFIF format
            if ( ( bytes[3] == ( byte ) 0x00E0 )
                && ( bytes[6] == 'J' )
                && ( bytes[7] == 'F' )
                && ( bytes[8] == 'I' )
                && ( bytes[9] == 'F' )
                && ( bytes[10] == 0x00 ) )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
                }
                
                return true;
            }
        // EXIF Format
            else if ( ( bytes[3] == ( byte ) 0x00E1 ) 
                    && ( bytes[6] == 'E' )
                    && ( bytes[7] == 'x' )
                    && ( bytes[8] == 'i' )
                    && ( bytes[9] == 'f' )
                    && ( bytes[10] == 0x00 ) )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
                }
                
                return true;
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
        }
        
        return false;
    }
}
