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
package org.apache.directory.api.ldap.codec.api;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.LdapMessageGrammar;
import org.apache.directory.api.ldap.codec.LdapStatesEnum;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;


/**
 * The LdapMessage container stores all the messages decoded by the Asn1Decoder.
 * When dealing with an encoding PDU, we will obtain a LdapMessage in the
 * container.
 *
 * @param <E> The decorated message
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapMessageContainer<E extends MessageDecorator<? extends Message>> extends AbstractContainer
{
    /** The Message decorator to store various temporary values */
    private E messageDecorator;

    /** checks if attribute is binary */
    private BinaryAttributeDetector binaryAttributeDetector;

    /** The message ID */
    private int messageId;

    /** The current control */
    private ControlDecorator<? extends Control> currentControl;

    /** The codec service */
    private final LdapApiService codec;


    /**
     * Creates a new LdapMessageContainer object. We will store ten grammars,
     * it's enough ...
     * 
     * @param codec The LDAP service instance
     */
    public LdapMessageContainer( LdapApiService codec )
    {
        this( codec, new DefaultConfigurableBinaryAttributeDetector() );
    }


    /**
     * Creates a new LdapMessageContainer object. We will store ten grammars,
     * it's enough ...
     *
     * @param codec The LDAP service instance
     * @param binaryAttributeDetector checks if an attribute is binary
     */
    public LdapMessageContainer( LdapApiService codec, BinaryAttributeDetector binaryAttributeDetector )
    {
        super();
        this.codec = codec;
        setGrammar( LdapMessageGrammar.getInstance() );
        this.binaryAttributeDetector = binaryAttributeDetector;
        setTransition( LdapStatesEnum.START_STATE );
    }


    /**
     * Gets the {@link LdapApiService} associated with this Container.
     *
     * @return The LDAP service instance
     */
    public LdapApiService getLdapCodecService()
    {
        return codec;
    }


    /**
     * @return Returns the ldapMessage.
     */
    public E getMessage()
    {
        return messageDecorator;
    }


    /**
     * Set a Message Object into the container. It will be completed by the
     * ldapDecoder.
     *
     * @param messageDecorator The message to set.
     */
    public void setMessage( E messageDecorator )
    {
        this.messageDecorator = messageDecorator;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clean()
    {
        super.clean();

        messageDecorator = null;
        messageId = 0;
        currentControl = null;
        setDecodedBytes( 0 );
    }


    /**
     * @return Returns true if the attribute is binary.
     * @param id checks if an attribute id is binary
     */
    public boolean isBinary( String id )
    {
        return binaryAttributeDetector.isBinary( id );
    }


    /**
     * @return The message ID
     */
    public int getMessageId()
    {
        return messageId;
    }


    /**
     * Set the message ID
     * @param messageId the id of the message
     */
    public void setMessageId( int messageId )
    {
        this.messageId = messageId;
    }


    /**
     * @return the current control being created
     */
    public ControlDecorator<? extends Control> getCurrentControl()
    {
        return currentControl;
    }


    /**
     * Store a newly created control
     * @param currentControl The control to store
     */
    public void setCurrentControl( ControlDecorator<? extends Control> currentControl )
    {
        this.currentControl = currentControl;
    }


    /**
     * Sets the binary attribute detector
     * 
     * @param binaryAttributeDetector the binary attribute detector
     */
    public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetector )
    {
        this.binaryAttributeDetector = binaryAttributeDetector;
    }


    /**
     * @return the binary attribute detector
     */
    public BinaryAttributeDetector getBinaryAttributeDetector()
    {
        return binaryAttributeDetector;
    }
}
