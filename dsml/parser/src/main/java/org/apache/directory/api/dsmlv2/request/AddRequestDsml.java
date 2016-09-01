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
package org.apache.directory.api.dsmlv2.request;


import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;


/**
 * DSML Decorator for AddRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddRequestDsml
    extends AbstractResultResponseRequestDsml<AddRequest, AddResponse>
    implements AddRequest
{

    /** The current attribute being decoded */
    private Attribute currentAttribute;


    /**
     * Creates a new getDecoratedMessage() of AddRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public AddRequestDsml( LdapApiService codec )
    {
        super( codec, new AddRequestImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of AddRequestDsml.
    *
     * @param codec The LDAP Service to use
    * @param ldapMessage the message to decorate
    */
    public AddRequestDsml( LdapApiService codec, AddRequest ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * Create a new attributeValue
     * 
     * @param type The attribute's name (called 'type' in the grammar)
     * @throws LdapException If we can't add the type
     */
    public void addAttributeType( String type ) throws LdapException
    {
        // do not create a new attribute if we have seen this attributeType before
        if ( getDecorated().getEntry().get( type ) != null )
        {
            currentAttribute = getDecorated().getEntry().get( type );
            return;
        }

        // fix this to use AttributeImpl(type.getString().toLowerCase())
        currentAttribute = new DefaultAttribute( type );
        getDecorated().getEntry().put( currentAttribute );
    }


    /**
     * @return Returns the currentAttribute type.
     */
    public String getCurrentAttributeType()
    {
        return currentAttribute.getId();
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If we can't add a new value
     */
    public void addAttributeValue( String value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If we can't add a new value
     */
    public void addAttributeValue( Value<?> value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If we can't add a new value
     */
    public void addAttributeValue( byte[] value ) throws LdapException
    {
        currentAttribute.add( value );
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
        Element element = super.toDsml( root );

        // Dn
        if ( getDecorated().getEntry() != null )
        {
            element.addAttribute( "dn", getDecorated().getEntry().getDn().getName() );
        }

        // Attributes
        Entry entry = getDecorated().getEntry();
        if ( entry != null )
        {
            for ( Attribute attribute : entry )
            {
                Element attributeElement = element.addElement( "attr" );
                attributeElement.addAttribute( "name", attribute.getId() );
                // Looping on Values
                for ( Value<?> value : attribute )
                {
                    if ( ParserUtils.needsBase64Encoding( value.getValue() ) )
                    {
                        Namespace xsdNamespace = new Namespace( "xsd", ParserUtils.XML_SCHEMA_URI );
                        Namespace xsiNamespace = new Namespace( "xsi", ParserUtils.XML_SCHEMA_INSTANCE_URI );
                        attributeElement.getDocument().getRootElement().add( xsdNamespace );
                        attributeElement.getDocument().getRootElement().add( xsiNamespace );

                        Element valueElement = attributeElement.addElement( "value" ).addText(
                            ParserUtils.base64Encode( value.getValue() ) );
                        valueElement
                            .addAttribute( new QName( "type", xsiNamespace ), "xsd:" + ParserUtils.BASE64BINARY );
                    }
                    else
                    {
                        attributeElement.addElement( "value" ).addText( value.getString() );
                    }
                }
            }
        }

        return element;
    }


    /**
     * Initialize the Entry.
     */
    public void initEntry()
    {
    }


    /**
     * Get the entry with its attributes.
     * 
     * @return Returns the entry.
     */
    public Entry getEntry()
    {
        return getDecorated().getEntry();
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to be added
     * @throws LdapException If we can't add a new value
     */
    public void addAttributeValue( Object value ) throws LdapException
    {
        if ( value instanceof Value<?> )
        {
            ( ( AddRequestDsml ) getDecorated() ).addAttributeValue( ( Value<?> ) value );
        }
        else if ( value instanceof String )
        {
            ( ( AddRequestDsml ) getDecorated() ).addAttributeValue( ( String ) value );
        }
        else if ( value instanceof byte[] )
        {
            ( ( AddRequestDsml ) getDecorated() ).addAttributeValue( ( byte[] ) value );
        }
    }


    /**
     * Get the added Dn
     * 
     * @return Returns the entry Dn.
     */
    public Dn getEntryDn()
    {
        return getDecorated().getEntryDn();
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest setEntryDn( Dn entryDn )
    {
        getDecorated().setEntryDn( entryDn );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest setEntry( Entry entry )
    {
        getDecorated().setEntry( entry );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest addControl( Control control )
    {
        return ( AddRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest addAllControls( Control[] controls )
    {
        return ( AddRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public AddRequest removeControl( Control control )
    {
        return ( AddRequest ) super.removeControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getResponseType()
    {
        return getDecorated().getResponseType();
    }
}
