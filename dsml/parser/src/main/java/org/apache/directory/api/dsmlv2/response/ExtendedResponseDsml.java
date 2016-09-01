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


import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.util.Strings;
import org.dom4j.Element;
import org.dom4j.Namespace;
import org.dom4j.QName;
import org.dom4j.tree.DefaultElement;


/**
 * DSML Decorator for ExtendedResponse
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ExtendedResponseDsml extends AbstractResultResponseDsml<ExtendedResponse>
    implements ExtendedResponse
{
    private static final String EXTENDED_RESPONSE_TAG = "extendedResponse";
    private byte[] response;


    /**
     * Creates a new getDecoratedMessage() of ExtendedResponseDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public ExtendedResponseDsml( LdapApiService codec )
    {
        super( codec, new ExtendedResponseImpl( "" ) );
    }


    /**
     * Creates a new getDecoratedMessage() of ExtendedResponseDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public ExtendedResponseDsml( LdapApiService codec, ExtendedResponse ldapMessage )
    {
        super( codec, ldapMessage );
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
            element = root.addElement( EXTENDED_RESPONSE_TAG );
        }
        else
        {
            element = new DefaultElement( EXTENDED_RESPONSE_TAG );
        }

        ExtendedResponse extendedResponse = getDecorated();

        // LDAP Result
        LdapResultDsml ldapResultDsml = new LdapResultDsml( getCodecService(),
            getDecorated().getLdapResult(), getDecorated() );
        ldapResultDsml.toDsml( element );

        // ResponseName
        String responseName = extendedResponse.getResponseName();
        if ( responseName != null )
        {
            element.addElement( "responseName" ).addText( responseName );
        }

        // Response
        Object responseValue = getResponseValue();

        if ( responseValue != null )
        {
            if ( ParserUtils.needsBase64Encoding( responseValue ) )
            {
                Namespace xsdNamespace = new Namespace( ParserUtils.XSD, ParserUtils.XML_SCHEMA_URI );
                Namespace xsiNamespace = new Namespace( ParserUtils.XSI, ParserUtils.XML_SCHEMA_INSTANCE_URI );
                element.getDocument().getRootElement().add( xsdNamespace );
                element.getDocument().getRootElement().add( xsiNamespace );

                Element responseElement = element.addElement( "response" )
                    .addText( ParserUtils.base64Encode( responseValue ) );
                responseElement.addAttribute( new QName( "type", xsiNamespace ), ParserUtils.XSD + ":"
                    + ParserUtils.BASE64BINARY );
            }
            else
            {
                element.addElement( "response" ).addText( Strings.utf8ToString( ( byte[] ) responseValue ) );
            }
        }

        return element;
    }


    /**
     * {@inheritDoc}
     */
    public void setResponseName( String oid )
    {
        getDecorated().setResponseName( oid );
    }


    /**
     * Get the extended response name
     * 
     * @return Returns the name.
     */
    public String getResponseName()
    {
        return getDecorated().getResponseName();
    }


    /**
     * Set the extended response name
     * 
     * @param responseName The name to set.
     */
    public void setResponseName( Oid responseName )
    {
        getDecorated().setResponseName( responseName.toString() );
    }


    /**
     * Get the extended response
     * 
     * @return Returns the response.
     */
    public byte[] getResponseValue()
    {
        return this.response;
    }


    /**
     * Set the extended response
     * 
     * @param responseValue The response to set.
     */
    public void setResponseValue( byte[] responseValue )
    {
        this.response = responseValue;
    }
}