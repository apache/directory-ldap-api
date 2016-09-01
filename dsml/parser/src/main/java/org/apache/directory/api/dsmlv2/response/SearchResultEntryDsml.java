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
package org.apache.directory.api.dsmlv2.response;


import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultEntryImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.dom4j.tree.DefaultElement;


/**
 * DSML Decorator for SearchResultEntry
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResultEntryDsml
    extends AbstractResponseDsml<SearchResultEntry>
    implements SearchResultEntry
{
    private static final String SEARCH_RESULT_ENTRY_TAG = "searchResultEntry";

    /** The current attribute being processed */
    private Attribute currentAttribute;


    /**
     * Creates a new getDecoratedMessage() of SearchResultEntryDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public SearchResultEntryDsml( LdapApiService codec )
    {
        super( codec, new SearchResultEntryImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of SearchResultEntryDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public SearchResultEntryDsml( LdapApiService codec, SearchResultEntry ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * @return The current ATtributeType
     */
    public Attribute getCurrentAttribute()
    {
        return currentAttribute;
    }


    /**
     * Create a new attribute
     * 
     * @param type The attribute's type
     * @throws LdapException If we can't add the new attributeType
     */
    public void addAttribute( String type ) throws LdapException
    {
        currentAttribute = new DefaultAttribute( type );

        getDecorated().getEntry().put( currentAttribute );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The added value
     * @throws LdapException If we can't add the new attributeType
     */
    public void addAttributeValue( Object value ) throws LdapException
    {
        if ( value instanceof String )
        {
            currentAttribute.add( ( String ) value );
        }
        else
        {
            currentAttribute.add( ( byte[] ) value );
        }
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = null;

        if ( root != null )
        {
            element = root.addElement( SEARCH_RESULT_ENTRY_TAG );
        }
        else
        {
            element = new DefaultElement( SEARCH_RESULT_ENTRY_TAG );
        }

        SearchResultEntry searchResultEntry = ( SearchResultEntry ) getDecorated();
        element.addAttribute( "dn", searchResultEntry.getObjectName().getName() );

        Entry entry = searchResultEntry.getEntry();
        for ( Attribute attribute : entry )
        {

            Element attributeElement = element.addElement( "attr" );
            attributeElement.addAttribute( "name", attribute.getUpId() );

            for ( Value<?> value : attribute )
            {
                if ( ParserUtils.needsBase64Encoding( value.getValue() ) )
                {
                    Namespace xsdNamespace = new Namespace( ParserUtils.XSD, ParserUtils.XML_SCHEMA_URI );
                    Namespace xsiNamespace = new Namespace( ParserUtils.XSI, ParserUtils.XML_SCHEMA_INSTANCE_URI );
                    Document doc = attributeElement.getDocument();

                    if ( doc != null )
                    {
                        Element docRoot = doc.getRootElement();
                        docRoot.add( xsdNamespace );
                        docRoot.add( xsiNamespace );
                    }

                    Element valueElement = attributeElement.addElement( "value" ).addText(
                        ParserUtils.base64Encode( value.getValue() ) );
                    valueElement.addAttribute( new QName( "type", xsiNamespace ), ParserUtils.XSD + ":"
                        + ParserUtils.BASE64BINARY );
                }
                else
                {
                    attributeElement.addElement( "value" ).addText( value.getString() );
                }
            }
        }

        return element;
    }


    /**
     * Get the entry Dn
     * 
     * @return Returns the objectName.
     */
    public Dn getObjectName()
    {
        return getDecorated().getObjectName();
    }


    /**
     * Set the entry Dn
     * 
     * @param objectName The objectName to set.
     */
    public void setObjectName( Dn objectName )
    {
        getDecorated().setObjectName( objectName );
    }


    /**
     * Get the entry.
     * 
     * @return Returns the entry.
     */
    public Entry getEntry()
    {
        return getDecorated().getEntry();
    }


    /**
     * Initialize the entry.
     * 
     * @param entry the entry
     */
    public void setEntry( Entry entry )
    {
        getDecorated().setEntry( entry );
    }
}
