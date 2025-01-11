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
package org.apache.directory.api.asn1.ber.grammar;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;


/**
 * The interface which expose common behavior of a Grammar implementer.
 *
 * @param <C> The container type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Grammar<C extends Asn1Container>
{
    /** The flag used to tell if a given state must have a follow up in the same PDU or not */
    enum FollowUp
    {
        /** When a following state is mandatory */
        MANDATORY,
        
        /** When a following state is optional */
        OPTIONAL;
    }
    
    /**
     * This method, when called, execute an action on the current data stored in
     * the container.
     *
     * @param asn1Container Store the data being processed.
     * @throws DecoderException Thrown when an unrecoverable error occurs.
     */
    void executeAction( C asn1Container ) throws DecoderException;


    /**
     * Get the grammar name
     *
     * @return Return the grammar's name
     */
    String getName();


    /**
     * Set the grammar's name
     *
     * @param name The grammar name
     */
    void setName( String name );
}
