/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.codec.api;


import java.util.Iterator;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.mina.filter.codec.ProtocolCodecFactory;


/**
 * The service interface for the LDAP codec. It gathers all the supported controls and extended operations.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public interface LdapApiService
{
    /** The default codec factory */
    String DEFAULT_PROTOCOL_CODEC_FACTORY =
        "org.apache.directory.api.ldap.codec.protocol.mina.LdapProtocolCodecFactory";


    // ------------------------------------------------------------------------
    // Control Methods
    // ------------------------------------------------------------------------

    /**
     * Returns an Iterator over the OID Strings of registered controls.
     * 
     * @return The registered control OID Strings
     */
    Iterator<String> registeredControls();


    /**
     * Checks if a control has been registered.
     * 
     * @param oid The Control OID we are looking for
     * @return The OID of the control to check for registration
     */
    boolean isControlRegistered( String oid );


    /**
     * Registers an {@link ControlFactory} with this service.
     * 
     * @param factory The control factory
     * @return The registred control factory
     */
    ControlFactory<?> registerControl( ControlFactory<?> factory );


    /**
     * Unregisters an {@link ControlFactory} with this service.
     * 
     * @param oid The oid of the control the factory is associated with.
     * @return The unregistred control factory
     */
    ControlFactory<?> unregisterControl( String oid );


    /**
     * Creates a new codec control decorator of the specified type.
     *
     * @param oid The OID of the new control to create.
     * @return The newly created codec control.
     */
    CodecControl<? extends Control> newControl( String oid );


    /**
     * Creates a new codec control decorator for the provided control.
     *
     * @param control The control the codec control is generated for.
     * @return The newly created codec control.
     */
    CodecControl<? extends Control> newControl( Control control );


    /**
     * Creates a JNDI control from the ldap model's control.
     *
     * @param modelControl The model's control.
     * @return The JNDI control.
     * @throws EncoderException if there are problems encoding the modelControl.
     */
    javax.naming.ldap.Control toJndiControl( Control modelControl ) throws EncoderException;


    /**
     * Creates a model control from the JNDI control.
     *
     * @param jndiControl The JNDI control.
     * @return The model control.
     * @throws DecoderException if there are problems decoding the value of the JNDI control.
     */
    Control fromJndiControl( javax.naming.ldap.Control jndiControl ) throws DecoderException;


    // ------------------------------------------------------------------------
    // Extended Request Methods
    // ------------------------------------------------------------------------

    /**
     * Returns an Iterator over the OID Strings of registered extended 
     * requests.
     *
     * @return The registered extended request OID Strings
     */
    Iterator<String> registeredExtendedRequests();


    /**
     * Registers an {@link ExtendedOperationFactory} for generating extended request 
     * response pairs.
     * 
     * @param factory The extended request factory
     * @return The displaced factory if one existed for the oid
     */
    ExtendedOperationFactory registerExtendedRequest( ExtendedOperationFactory factory );


    /**
     * Unregisters an {@link ExtendedOperationFactory} for generating extended 
     * request response pairs.
     * 
     * @param oid The extended request oid
     * @return The displaced factory if one existed for the oid
     */
    ExtendedOperationFactory unregisterExtendedRequest( String oid );


    /**
     * Checks to see if an extended operation, either a standard request 
     * response, pair or just an unsolicited response is registered.
     *
     * @param oid The object identifier for the extended operation
     * @return true if registered, false if not
     */
    boolean isExtendedOperationRegistered( String oid );


    // ------------------------------------------------------------------------
    // Extended Response Methods
    // ------------------------------------------------------------------------

    /**
     * Creates a model ExtendedResponse from the JNDI ExtendedResponse.
     *
     * @param jndiResponse The JNDI ExtendedResponse 
     * @return The model ExtendedResponse
     * @throws DecoderException if the response value cannot be decoded.
     */
    ExtendedResponse fromJndi( javax.naming.ldap.ExtendedResponse jndiResponse ) throws DecoderException;


    /**
     * Creates a JNDI {@link javax.naming.ldap.ExtendedResponse} from the model 
     * {@link ExtendedResponse}.
     * 
     * @param modelResponse The extended response to convert
     * @return A JNDI extended response
     * @throws EncoderException If the conversion failed
     */
    javax.naming.ldap.ExtendedResponse toJndi( ExtendedResponse modelResponse ) throws EncoderException;


    /**
     * Creates a model ExtendedResponse from the JNDI ExtendedRequest.
     *
     * @param jndiRequest The JNDI ExtendedRequest 
     * @return The model ExtendedRequest
     * @throws DecoderException if the request value cannot be decoded.
     */
    ExtendedRequest fromJndi( javax.naming.ldap.ExtendedRequest jndiRequest ) throws DecoderException;


    /**
     * Creates a JNDI {@link javax.naming.ldap.ExtendedRequest} from the model 
     * {@link ExtendedRequest}.
     * 
     * @param modelRequest The extended request to convert
     * @return A JNDI extended request
     * @throws EncoderException If the conversion failed
     */
    javax.naming.ldap.ExtendedRequest toJndi( ExtendedRequest modelRequest ) throws EncoderException;


    // ------------------------------------------------------------------------
    // Other Methods
    // ------------------------------------------------------------------------

    /**
     * Creates a new LDAP {@link ProtocolCodecFactory}.
     *
     * @return the {@link ProtocolCodecFactory}
     */
    ProtocolCodecFactory getProtocolCodecFactory();


    /**
     * Registers a ProtocolCodecFactory with this LdapCodecService.
     *
     * @param factory The factory being registered.
     * @return The previously set {@link ProtocolCodecFactory}, or null if 
     * none had been set earlier.
     */
    ProtocolCodecFactory registerProtocolCodecFactory( ProtocolCodecFactory factory );


    /**
     * Creates a new MessageContainer.
     *
     * @return The newly created LDAP MessageContainer instance.
     */
    Asn1Container newMessageContainer();


    /**
     * Create an instance of a ExtendedResponse, knowing its OID. Inject the payload
     * into it.
     * 
     * @param responseName The extendedRespose OID
     * @param messageId The original message ID
     * @param serializedResponse The serialized response payload
     * @param <E> The extended response type
     * @return The extendedResponse instance
     * 
     * @throws DecoderException If the payload is incorrect
     */
    <E extends ExtendedResponse> E newExtendedResponse( String responseName, int messageId, byte[] serializedResponse )
        throws DecoderException;


    /**
     * Creates a new ExtendedRequest instance.
     * 
     * @param oid the extended request's object identifier
     * @param value the encoded value of the extended request
     * @return The new extended request
     */
    ExtendedRequest newExtendedRequest( String oid, byte[] value );


    /**
     * Decorates an extended request message, ie encapsulate it into a class that do the encoding/decoding
     *
     * @param decoratedMessage The extended request to decorate
     * @return The decorated extended request
     */
    ExtendedRequestDecorator<?> decorate( ExtendedRequest decoratedMessage );


    /**
     * Decorates an extended response message, ie encapsulate it into a class that do the encoding/decoding
     *
     * @param decoratedMessage The extended response to decorate
     * @return The decorated extended response
     */
    ExtendedResponseDecorator<?> decorate( ExtendedResponse decoratedMessage );
}
