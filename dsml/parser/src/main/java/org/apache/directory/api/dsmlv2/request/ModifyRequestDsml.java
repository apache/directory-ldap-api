/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
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

import org.apache.commons.text.StringEscapeUtils;
import org.apache.directory.api.dsmlv2.DsmlLiterals;
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
     * Get the cirrent attribute's type
     * 
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
    @Override
    public Element toDsml( Element root )
    {
        Element element = super.toDsml( root );

        ModifyRequest request = getDecorated();

        // Dn
        if ( request.getName() != null )
        {
            element.addAttribute( DsmlLiterals.DN, request.getName().getName() );
        }

        // Modifications
        Collection<Modification> modifications = request.getModifications();

        for ( Modification modification : modifications )
        {
            Element modElement = element.addElement( DsmlLiterals.MODIFICATION );

            if ( modification.getAttribute() != null )
            {
                modElement.addAttribute( DsmlLiterals.NAME, modification.getAttribute().getId() );

                for ( Value value : modification.getAttribute() )
                {
                    if ( value.isHumanReadable() )
                    {
                        modElement.addElement( DsmlLiterals.VALUE ).setText( StringEscapeUtils.escapeXml11( value.getString() ) );
                    }
                    else
                    {
                        Namespace xsdNamespace = new Namespace( ParserUtils.XSD, ParserUtils.XML_SCHEMA_URI );
                        Namespace xsiNamespace = new Namespace( ParserUtils.XSI, ParserUtils.XML_SCHEMA_INSTANCE_URI );
                        element.getDocument().getRootElement().add( xsdNamespace );
                        element.getDocument().getRootElement().add( xsiNamespace );

                        Element valueElement = modElement.addElement( DsmlLiterals.VALUE ).addText(
                            ParserUtils.base64Encode( value.getString() ) );
                        valueElement.addAttribute( new QName( DsmlLiterals.TYPE, xsiNamespace ), ParserUtils.XSD_COLON
                            + ParserUtils.BASE64BINARY );
                    }
                }
            }

            ModificationOperation operation = modification.getOperation();

            if ( operation == ModificationOperation.ADD_ATTRIBUTE )
            {
                modElement.addAttribute( DsmlLiterals.OPERATION, DsmlLiterals.ADD );
            }
            else if ( operation == ModificationOperation.REPLACE_ATTRIBUTE )
            {
                modElement.addAttribute( DsmlLiterals.OPERATION, DsmlLiterals.REPLACE );
            }
            else if ( operation == ModificationOperation.REMOVE_ATTRIBUTE )
            {
                modElement.addAttribute( DsmlLiterals.OPERATION, DsmlLiterals.DELETE );
            }
            else if ( operation == ModificationOperation.INCREMENT_ATTRIBUTE )
            {
                modElement.addAttribute( DsmlLiterals.OPERATION, DsmlLiterals.INCREMENT );
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
    @Override
    public MessageTypeEnum getResponseType()
    {
        return getDecorated().getResponseType();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Modification> getModifications()
    {
        return getDecorated().getModifications();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Modification mod )
    {
        getDecorated().addModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeModification( Modification mod )
    {
        getDecorated().removeModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
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
    @Override
    public ModifyRequest remove( Attribute attr )
    {
        getDecorated().remove( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( String attributeName )
    {
        getDecorated().remove( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Attribute attr, ModificationOperation modOp )
    {
        getDecorated().addModification( attr, modOp );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
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
    @Override
    public ModifyRequest add( Attribute attr )
    {
        getDecorated().add( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest replace( String attributeName )
    {
        getDecorated().replace( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
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
    @Override
    public ModifyRequest replace( Attribute attr )
    {
        getDecorated().replace( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest increment( Attribute attributeName )
    {
        getDecorated().increment( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest increment( Attribute attributeName, int increment )
    {
        getDecorated().increment( attributeName, increment );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest increment( String attr )
    {
        getDecorated().increment( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest increment( String attr, int increment )
    {
        getDecorated().increment( attr, increment );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addControl( Control control )
    {
        return ( ModifyRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addAllControls( Control[] controls )
    {
        return ( ModifyRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeControl( Control control )
    {
        return ( ModifyRequest ) super.removeControl( control );
    }
}
