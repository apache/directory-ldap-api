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


import java.util.Collection;

import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.name.Dn;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;


/**
 * DSML Decorator for ModifyRequest
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyRequestDsml
    extends AbstractResultResponseRequestDsml<ModifyRequest, ModifyResponse>
    implements ModifyRequest
{

    /** The current attribute being decoded */
    private Attribute currentAttribute;

    /** A local storage for the operation */
    private ModificationOperation currentOperation;


    /**
     * Creates a new getDecoratedMessage() of ModifyRequestDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public ModifyRequestDsml( LdapApiService codec )
    {
        super( codec, new ModifyRequestImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of ModifyRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public ModifyRequestDsml( LdapApiService codec, ModifyRequest ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * @return the current attribute's type
     */
    public String getCurrentAttributeType()
    {
        return currentAttribute.getId();
    }


    /**
     * Store the current operation
     * 
     * @param currentOperation The currentOperation to set.
     */
    public void setCurrentOperation( int currentOperation )
    {
        this.currentOperation = ModificationOperation.getOperation( currentOperation );
    }


    /**
     * Add a new attributeTypeAndValue
     * 
     * @param type The attribute's name
     */
    public void addAttributeTypeAndValues( String type )
    {
        currentAttribute = new DefaultAttribute( type );

        Modification modification = new DefaultModification( currentOperation, currentAttribute );
        getDecorated().addModification( modification );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If we can't add a value
     */
    public void addAttributeValue( byte[] value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If we can't add a value
     */
    public void addAttributeValue( String value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = super.toDsml( root );

        ModifyRequest request = getDecorated();

        // Dn
        if ( request.getName() != null )
        {
            element.addAttribute( "dn", request.getName().getName() );
        }

        // Modifications
        Collection<Modification> modifications = request.getModifications();

        for ( Modification modification : modifications )
        {
            Element modElement = element.addElement( "modification" );

            if ( modification.getAttribute() != null )
            {
                modElement.addAttribute( "name", modification.getAttribute().getId() );

                for ( Value<?> value : modification.getAttribute() )
                {
                    if ( value.getValue() != null )
                    {
                        if ( ParserUtils.needsBase64Encoding( value.getValue() ) )
                        {
                            Namespace xsdNamespace = new Namespace( "xsd", ParserUtils.XML_SCHEMA_URI );
                            Namespace xsiNamespace = new Namespace( "xsi", ParserUtils.XML_SCHEMA_INSTANCE_URI );
                            element.getDocument().getRootElement().add( xsdNamespace );
                            element.getDocument().getRootElement().add( xsiNamespace );

                            Element valueElement = modElement.addElement( "value" ).addText(
                                ParserUtils.base64Encode( value.getValue() ) );
                            valueElement.addAttribute( new QName( "type", xsiNamespace ), "xsd:"
                                + ParserUtils.BASE64BINARY );
                        }
                        else
                        {
                            modElement.addElement( "value" ).setText( value.getString() );
                        }
                    }
                }
            }

            ModificationOperation operation = modification.getOperation();

            if ( operation == ModificationOperation.ADD_ATTRIBUTE )
            {
                modElement.addAttribute( "operation", "add" );
            }
            else if ( operation == ModificationOperation.REPLACE_ATTRIBUTE )
            {
                modElement.addAttribute( "operation", "replace" );
            }
            else if ( operation == ModificationOperation.REMOVE_ATTRIBUTE )
            {
                modElement.addAttribute( "operation", "delete" );
            }
        }

        return element;
    }


    //-------------------------------------------------------------------------
    // The ModifyRequest methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getResponseType()
    {
        return getDecorated().getResponseType();
    }


    /**
     * {@inheritDoc}
     */
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public Collection<Modification> getModifications()
    {
        return getDecorated().getModifications();
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest addModification( Modification mod )
    {
        getDecorated().addModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest removeModification( Modification mod )
    {
        getDecorated().removeModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( String attributeName, String... attributeValue )
    {
        getDecorated().remove( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( String attributeName, byte[]... attributeValue )
    {
        getDecorated().remove( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( Attribute attr )
    {
        getDecorated().remove( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( String attributeName )
    {
        getDecorated().remove( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest addModification( Attribute attr, ModificationOperation modOp )
    {
        getDecorated().addModification( attr, modOp );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest add( String attributeName, String... attributeValue )
    {
        getDecorated().add( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest add( String attributeName, byte[]... attributeValue )
    {
        getDecorated().add( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest add( Attribute attr )
    {
        getDecorated().add( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest replace( String attributeName )
    {
        getDecorated().replace( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest replace( String attributeName, String... attributeValue )
    {
        getDecorated().replace( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest replace( String attributeName, byte[]... attributeValue )
    {
        getDecorated().replace( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest replace( Attribute attr )
    {
        getDecorated().replace( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest addControl( Control control )
    {
        return ( ModifyRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest addAllControls( Control[] controls )
    {
        return ( ModifyRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest removeControl( Control control )
    {
        return ( ModifyRequest ) super.removeControl( control );
    }
}
