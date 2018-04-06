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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.Hex;
import org.apache.directory.api.util.Strings;


/**
 * A Dn Name component Normalizer which uses the bootstrap registries to find
 * the appropriate normalizer for the attribute of the name component with which
 * to normalize the name component value.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ConcreteNameComponentNormalizer implements NameComponentNormalizer
{
    /** the schemaManager used to dynamically resolve Normalizers */
    private final SchemaManager schemaManager;


    /**
     * Creates a Dn Name component Normalizer which uses the bootstrap
     * registries to find the appropriate normalizer for the attribute of the
     * name component with which to normalize the name component value.
     *
     * @param schemaManager the schemaManager used to dynamically resolve Normalizers
     */
    public ConcreteNameComponentNormalizer( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }


    private String unescape( String value )
    {
        char[] newVal = new char[value.length()];
        int escaped = 0;
        char high = 0;
        char low;
        int pos = 0;

        for ( int index = 0; index < value.length(); index++  )
        {
            char c = value.charAt( index );
            
            switch ( escaped )
            {
                case 0:
                    if ( c == '\\' )
                    {
                        escaped = 1;
                    }
                    else
                    {
                        newVal[pos++] = c;
                    }

                    break;

                case 1:
                    escaped++;
                    high = c;
                    break;

                case 2:
                    escaped = 0;
                    low = c;
                    newVal[pos++] = ( char ) Hex.getHexValue( high, low );
                    break;

                default:
                    throw new IllegalStateException( I18n.err( I18n.ERR_13713_ESCAPED_WRONG_VALUE, value ) );
            }
        }

        return new String( newVal, 0, pos );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object normalizeByName( String name, String value ) throws LdapException
    {
        AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry( name );
        Normalizer normalizer = lookup( name );

        if ( attributeType.getSyntax().isHumanReadable() )
        {
            return normalizer.normalize( value );
        }
        else
        {
            String unescaped = unescape( value );

            return normalizer.normalize( unescaped );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object normalizeByName( AttributeType attributeType, String value ) throws LdapException
    {
        MatchingRule mrule = attributeType.getEquality();
        Normalizer normalizer;
            
        if ( mrule == null )
        {
            return new NoOpNormalizer( attributeType.getOid() );
        }
        else
        {
            normalizer = attributeType.getEquality().getNormalizer();
        }

        if ( attributeType.getSyntax().isHumanReadable() )
        {
            return normalizer.normalize( value );
        }
        else
        {
            String unescaped = unescape( value );

            return normalizer.normalize( unescaped );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object normalizeByName( String name, byte[] value ) throws LdapException
    {
        AttributeType attributeType = schemaManager.getAttributeType( name );
        
        return new Value( attributeType, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object normalizeByOid( String oid, String value ) throws LdapException
    {
        return lookup( oid ).normalize( value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object normalizeByOid( String oid, byte[] value ) throws LdapException
    {
        return lookup( oid ).normalize( Strings.utf8ToString( value ) );
    }


    /**
     * Looks up the Normalizer to use for a name component using the attributeId
     * for the name component.  First the attribute is resolved, then its
     * equality matching rule is looked up.  The normalizer of that matching
     * rule is returned.
     *
     * @param id the name or oid of the attribute in the name component to
     * normalize the value of
     * @return the Normalizer to use for normalizing the value of the attribute
     * @throws LdapException if there are failures resolving the Normalizer
     */
    private Normalizer lookup( String id ) throws LdapException
    {
        AttributeType type = schemaManager.lookupAttributeTypeRegistry( id );
        MatchingRule mrule = type.getEquality();

        if ( mrule == null )
        {
            return new NoOpNormalizer( id );
        }

        return mrule.getNormalizer();
    }


    /**
     * @see NameComponentNormalizer#isDefined(String)
     */
    @Override
    public boolean isDefined( String id )
    {
        return schemaManager.getAttributeTypeRegistry().contains( id );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String normalizeName( String attributeName ) throws LdapException
    {
        return schemaManager.getAttributeTypeRegistry().getOidByName( attributeName );
    }
}
