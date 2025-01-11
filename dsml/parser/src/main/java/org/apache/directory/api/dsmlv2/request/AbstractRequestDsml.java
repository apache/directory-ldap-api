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


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.dsmlv2.AbstractDsmlMessageDecorator;
import org.apache.directory.api.dsmlv2.DsmlLiterals;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Request;
import org.dom4j.Element;


/**
 * Abstract class for DSML requests.
 *
 * @param <E> The request type
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractRequestDsml<E extends Request>
    extends AbstractDsmlMessageDecorator<E>
    implements Request
{
    /**
     * Creates a new instance of AbstractRequestDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public AbstractRequestDsml( LdapApiService codec, E ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * Creates the Request Element and adds RequestID and Controls.
     *
     * @param root the root element
     * @return the Request Element of the given name containing
     */
    @Override
    public Element toDsml( Element root )
    {
        Element element = root.addElement( getRequestName() );

        // Request ID
        int requestID = getDecorated().getMessageId();
        if ( requestID > 0 )
        {
            element.addAttribute( DsmlLiterals.REQUEST_ID, Integer.toString( requestID ) );
        }

        // Controls
        ParserUtils.addControls( getCodecService(), element, getDecorated().getControls().values(), true );

        return element;
    }


    /**
     * Gets the name of the request according to the type of the decorated element.
     *
     * @return the name of the request according to the type of the decorated element.
     */
    protected String getRequestName()
    {
        switch ( getDecorated().getType() )
        {
            case ABANDON_REQUEST:
                return DsmlLiterals.ABANDON_REQUEST;

            case ADD_REQUEST:
                return DsmlLiterals.ADD_REQUEST;

            case BIND_REQUEST:
                return DsmlLiterals.AUTH_REQUEST;

            case COMPARE_REQUEST:
                return DsmlLiterals.COMPARE_REQUEST;

            case DEL_REQUEST:
                return DsmlLiterals.DEL_REQUEST;

            case EXTENDED_REQUEST:
                return DsmlLiterals.EXTENDED_REQUEST;

            case MODIFYDN_REQUEST:
                return DsmlLiterals.MOD_DN_REQUEST;

            case MODIFY_REQUEST:
                return DsmlLiterals.MODIFY_REQUEST;

            case SEARCH_REQUEST:
                return DsmlLiterals.SEARCH_REQUEST;

            default:
                return DsmlLiterals.ERROR;
        }
    }


    /**
     * Get the length of the encoded request
     * 
     * @return the buffer's length (always 0)
     */
    public int computeLength()
    {
        return 0;
    }


    /**
     * Encode the request. Always return an empty buffer.
     *
     * @param buffer The buffer to allocate
     * @return The resulting buffer
     * @throws EncoderException If we had an error while encoding the request
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        return null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasResponse()
    {
        return getDecorated().hasResponse();
    }
}
