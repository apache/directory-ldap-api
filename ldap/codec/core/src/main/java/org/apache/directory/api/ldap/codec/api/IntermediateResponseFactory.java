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


import org.apache.directory.api.ldap.model.message.IntermediateResponse;


/**
 * The factory interface, defined by the codec API, for creating new 
 * Intermediate responses.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface IntermediateResponseFactory
{
    /**
     * Gets the OID of the IntermediateResponse this factory generates.
     *
     * @return the extended request OID
     */
    String getOid();


    /**
     * Returns a new {@link IntermediateResponseDecorator} with the following encoded value.
     * 
     * @param value the encoded value
     * @return the decorator for the extended response type
     */
    IntermediateResponse newResponse( byte[] value );


    /**
     * Decorates an IntermediateResponse which may or may not be of the expected 
     * type. The factory implementor must check and handle appropriately.
     *
     * @param decoratedMessage the message to be decorated.
     * @return The decorated message 
     */
    IntermediateResponse decorate( IntermediateResponse decoratedMessage );
}
