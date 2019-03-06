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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * The factory interface, defined by the codec API, for creating new 
 * requests/responses for extended operations.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public interface ExtendedOperationFactory
{
    /**
     * Gets the OID of the extended requests this factory generates.
     *
     * @return the extended request OID
     */
    String getOid();


    /**
     * Returns a new {@link ExtendedRequest} with no value
     * 
     * @return the decorator for the extended request type
     */
    ExtendedRequest newRequest();


    /**
     * Returns a new {@link ExtendedRequest} with the following encoded value.
     * 
     * @param value the encoded value
     * @return the decorator for the extended request type
     * @throws DecoderException If we can't decode the response
     */
    ExtendedRequest newRequest( byte[] value ) throws DecoderException;


    /**
     * Creates a new ExtendedResponse, for the ExtendedRequest with no value
     * 
     * @return The new ExtendedResponse.
     * @throws DecoderException If the response cannot be decoded
     */
    ExtendedResponse newResponse() throws DecoderException;


    /**
     * Creates a new ExtendedResponse, for the ExtendedRequest with a specific
     * encoded value.
     * 
     * @param encodedValue The encoded value for the ExtendedResponse instance.
     * @return The new ExtendedResponse.
     * @throws DecoderException If we can't decode the response
     */
    ExtendedResponse newResponse( byte[] encodedValue ) throws DecoderException;


    /**
     * Encode the value part of the extended request operation.
     *
     * @param buffer The buffer into which to put the encoded value
     * @param extendedRequest The ExtendedRequest Operation to encode
     */
    void encodeValue( Asn1Buffer buffer, ExtendedRequest extendedRequest );


    /**
     * Decode the value part of the extended request operation.
     *
     * @param extendedRequest The ExtendedRequest Operation to feed
     * @param requestValue The request value to decode
     * @throws DecoderException If the value cannot be decoded
     */
    void decodeValue( ExtendedRequest extendedRequest, byte[] requestValue ) throws DecoderException;


    /**
     * Encode the value part of the extended response operation.
     *
     * @param buffer The buffer into which to put the encoded value
     * @param extendedResponse The ExtendedResponse Operation to encode
     */
    void encodeValue( Asn1Buffer buffer, ExtendedResponse extendedResponse );


    /**
     * Decode the value part of the extended response operation.
     *
     * @param extendedResponse The ExtendedResponse Operation to feed
     * @param responseValue The response value to decode
     * @throws DecoderException If the value cannot be decoded
     */
    void decodeValue( ExtendedResponse extendedResponse, byte[] responseValue ) throws DecoderException;
}
