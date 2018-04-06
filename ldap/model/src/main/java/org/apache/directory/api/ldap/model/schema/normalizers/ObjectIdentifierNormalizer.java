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
package org.apache.directory.api.ldap.model.schema.normalizers;


import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.PrepareString;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Strings;


/**
 * A normalizer for the objectIdentifierMatch matching rule.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class ObjectIdentifierNormalizer extends Normalizer
{
    /** A reference to the schema manager used to normalize the Name */
    private transient SchemaManager schemaManager;

    /**
     * Creates a new instance of ObjectIdentifierNormalizer.
     */
    public ObjectIdentifierNormalizer()
    {
        super( SchemaConstants.OBJECT_IDENTIFIER_MATCH_MR_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String normalize( String value ) throws LdapException
    {
        if ( Strings.isEmpty( value ) )
        {
            return "";
        }
        
        String trimmedValue = value.trim();
        
        if ( Strings.isEmpty( trimmedValue ) )
        {
            return "";
        }

        String oid = schemaManager.getRegistries().getOid( trimmedValue );
        
        if ( oid == null )
        {
            // Not found in the schemaManager : keep it as is
            if ( Oid.isOid( trimmedValue ) )
            {
                // It's an numericOid
                oid = trimmedValue;
            }
            else
            {
                // It's a descr : ALPHA ( ALPHA | DIGIT | '-' )*
                for ( int i = 0; i < trimmedValue.length(); i++ )
                {
                    char c = trimmedValue.charAt( i );
                    
                    if ( i == 0 )
                    {
                        if ( !Character.isLetter( c ) )
                        {
                            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, I18n.err(
                                I18n.ERR_13724_INVALID_VALUE, value ) );
                        }
                    }
                    else
                    {
                        if ( !( Character.isDigit( c ) || Character.isLetter( c ) || ( c == '-'  ) || ( c == '_' ) ) )
                            {
                            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX, I18n.err(
                                I18n.ERR_13724_INVALID_VALUE, value ) );
                            }
                    }
                }
                
                oid = trimmedValue;
            }
        }
        
        return oid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String normalize( String value, PrepareString.AssertionType assertionType ) throws LdapException
    {
        return normalize( value );
    }
}
