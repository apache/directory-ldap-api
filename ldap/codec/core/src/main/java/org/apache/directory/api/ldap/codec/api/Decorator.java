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


import org.apache.directory.api.asn1.Asn1Object;


/**
 * The codec uses this interface to add additional information to LDAP Model
 * objects during encoding and decoding,
 *
 * @param <E> The element to decorate
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Decorator<E> extends Asn1Object
{
    /**
     * Gets the object being decorated by this IDecorator.
     *
     * @return The decorated object
     */
    E getDecorated();


    /**
     * Gets the codec service responsible for managing the encoding and 
     * decoding of the decorated objects.
     * 
     * @return the codec service
     */
    LdapApiService getCodecService();
}
