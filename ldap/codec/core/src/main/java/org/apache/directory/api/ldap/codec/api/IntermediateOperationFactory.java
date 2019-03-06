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
import org.apache.directory.api.ldap.model.message.IntermediateResponse;


/**
 * The factory interface, defined by the codec API, for creating new 
 * Intermediate responses.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface IntermediateOperationFactory
{
    /**
     * Gets the OID of the IntermediateResponse this factory generates.
     *
     * @return the extended request OID
     */
    String getOid();


    /**
     * Returns a new {@link IntermediateResponse} with no value.
     * 
     * @return the extended response type
     */
    IntermediateResponse newResponse();


    /**
     * Returns a new {@link IntermediateResponse} with the following encoded value.
     * 
     * @param value the encoded value
     * @return the extended response type
     */
    IntermediateResponse newResponse( byte[] value );


    /**
     * Encode the value part of the intermediate response operation.
     *
     * @param buffer The buffer into which to put the encoded value
     * @param intermediateResponse The IntermediateResponse Operation to encode
     */
    void encodeValue( Asn1Buffer buffer, IntermediateResponse intermediateResponse );


    /**
     * Decode the value part of the intermediate response operation.
     *
     * @param intermediateResponse The IntermediateResponse Operation to feed
     * @param responseValue The response value to decode
     * @throws DecoderException If the value cannot be decoded
     */
    void decodeValue( IntermediateResponse intermediateResponse, byte[] responseValue ) throws DecoderException;
}
