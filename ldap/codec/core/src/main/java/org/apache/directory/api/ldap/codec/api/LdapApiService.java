/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import java.util.Map;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.name.DnFactory;
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
     * Returns an Iterator over the OID Strings of registered request controls.
     *
     * @return The registered control OID Strings
     */
    Iterator<String> registeredRequestControls();


    /**
     * Returns an Iterator over the OID Strings of registered response controls.
     *
     * @return The registered control OID Strings
     */
    Iterator<String> registeredResponseControls();


    /**
     * Checks if a control has been registered. It will check in both the
     * request and response control maps.
     *
     * @param oid The Control OID we are looking for
     * @return The OID of the control to check for registration
     */
    boolean isControlRegistered( String oid );


    /**
     * Registers an request {@link ControlFactory} with this service.
     *
     * @param factory The control factory
     * @return The registered control factory
     */
    ControlFactory<?> registerRequestControl( ControlFactory<?> factory );


    /**
     * Registers an response {@link ControlFactory} with this service.
     *
     * @param factory The control factory
     * @return The registered control factory
     */
    ControlFactory<?> registerResponseControl( ControlFactory<?> factory );


    /**
     * Unregisters a request {@link ControlFactory} with this service.
     *
     * @param oid The oid of the control the factory is associated with.
     * @return The unregistered control factory
     */
    ControlFactory<?> unregisterRequestControl( String oid );


    /**
     * Unregisters a response {@link ControlFactory} with this service.
     *
     * @param oid The oid of the control the factory is associated with.
     * @return The unregistered control factory
     */
    ControlFactory<?> unregisterResponseControl( String oid );


    /**
     * Creates a JNDI control from the ldap model's control.
     *
     * @param modelControl The model's control.
     * @return The JNDI control.
     * @throws EncoderException if there are problems encoding the modelControl.
     */
    javax.naming.ldap.Control toJndiControl( Control modelControl ) throws EncoderException;


    /**
     * Creates a model request control from the JNDI request control.
     *
     * @param jndiControl The JNDI control.
     * @return The model request control.
     * @throws DecoderException if there are problems decoding the value of the JNDI control.
     */
    Control fromJndiRequestControl( javax.naming.ldap.Control jndiControl ) throws DecoderException;


    /**
     * Creates a model response control from the JNDI response control.
     *
     * @param jndiControl The JNDI response control.
     * @return The model control.
     * @throws DecoderException if there are problems decoding the value of the JNDI control.
     */
    Control fromJndiResponseControl( javax.naming.ldap.Control jndiControl ) throws DecoderException;


    /**
     * @return the request controlFactories
     */
    Map<String, ControlFactory<? extends Control>> getRequestControlFactories();


    /**
     * @return the response controlFactories
     */
    Map<String, ControlFactory<? extends Control>> getResponseControlFactories();


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
     * Returns an Iterator over the OID Strings of registered extended
     * responses.
     *
     * @return The registered extended response OID Strings
     */
    Iterator<String> registeredExtendedResponses();


    /**
     * Registers an {@link ExtendedOperationFactory} for generating extended request
     * response pairs.
     *
     * @param factory The extended request factory
     * @return The registered factory if one existed for the oid
     */
    ExtendedOperationFactory registerExtendedRequest( ExtendedOperationFactory factory );


    /**
     * Registers an {@link ExtendedOperationFactory} for generating extended response
     * response pairs.
     *
     * @param factory The extended response factory
     * @return The registered factory if one existed for the oid
     */
    ExtendedOperationFactory registerExtendedResponse( ExtendedOperationFactory factory );


    /**
     * Unregisters an {@link ExtendedOperationFactory} for generating extended
     * request response pairs.
     *
     * @param oid The extended request oid
     * @return The registered factory if one existed for the oid
     */
    ExtendedOperationFactory unregisterExtendedRequest( String oid );


    /**
     * Unregisters an {@link ExtendedOperationFactory} for generating extended
     * responses.
     *
     * @param oid The extended response oid
     * @return The registered factory if one existed for the oid
     */
    ExtendedOperationFactory unregisterExtendedResponse( String oid );


    /**
     * Checks to see if an extended request operation is registered.
     *
     * @param oid The object identifier for the extended request operation
     * @return true if registered, false if not
     */
    boolean isExtendedRequestRegistered( String oid );


    /**
     * Checks to see if an extended response operation is registered.
     *
     * @param oid The object identifier for the extended response operation
     * @return true if registered, false if not
     */
    boolean isExtendedResponseRegistered( String oid );
    
    
    /**
     * @return the extendedRequestFactories
     */
    Map<String, ExtendedOperationFactory> getExtendedRequestFactories();


    /**
     * @return the extendedResponseFactories
     */
    Map<String, ExtendedOperationFactory> getExtendedResponseFactories();


    // ------------------------------------------------------------------------
    // Intermediate Response Methods
    // ------------------------------------------------------------------------

    /**
     * Returns an Iterator over the OID Strings of registered intermediate
     * responses.
     *
     * @return The registered Intermediate response OID Strings
     */
    Iterator<String> registeredIntermediateResponses();


    /**
     * Registers an {@link IntermediateOperationFactory} for generating intermediate response
     *
     * @param factory The intermediate response factory
     * @return The displaced factory if one existed for the oid
     */
    IntermediateOperationFactory registerIntermediateResponse( IntermediateOperationFactory factory );


    /**
     * Unregisters an {@link IntermediateOperationFactory} for generating intermediate
     * response
     *
     * @param oid The intermediate response oid
     * @return The displaced factory if one existed for the oid
     */
    IntermediateOperationFactory unregisterIntermediateResponse( String oid );


    /**
     * Checks to see if an intermediate response is registered.
     *
     * @param oid The object identifier for the intermediate response
     * @return true if registered, false if not
     */
    boolean isIntermediateResponseRegistered( String oid );


    /**
     * @return the intermediateResponseFactories
     */
    Map<String, IntermediateOperationFactory> getIntermediateResponseFactories();


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
     * Associate a DnFactory to the service
     * @param dnfactory The DnFactory instance
     */
    void setDnfactory( DnFactory dnfactory );
    
    
    /**
     * Get the DN Factory
     * @return The DnFactory instance
     */
    DnFactory getDnFactory();
}
