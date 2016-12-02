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
package org.apache.directory.api.ldap.model.message;


/**
 * An enum to store the Ldap message type.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum MessageTypeEnum
{
    /** The AbandonRequest message */
    ABANDON_REQUEST,
    
    /** The AddResquest message */
    ADD_REQUEST,
    
    /** The Response message */
    ADD_RESPONSE,
    
    /** The BindRequest message */
    BIND_REQUEST,
    
    /** The BindResponse message */
    BIND_RESPONSE,
    
    /** The  ompareRequest message */
    COMPARE_REQUEST,
    
    /** The CompareResponse message */
    COMPARE_RESPONSE,
    
    /** The DelRequest message */
    DEL_REQUEST,
    
    /** The DelResponse message */
    DEL_RESPONSE,
    
    /** The ExtendedRequest message */
    EXTENDED_REQUEST,
    
    /** The ExtendedResponse message */
    EXTENDED_RESPONSE,
    
    /** The ModifyDNRequest message */
    MODIFYDN_REQUEST,
    
    /** The ModifyDNResponse message */
    MODIFYDN_RESPONSE,
    
    /** The ModifyRequest message */
    MODIFY_REQUEST,
    
    /** The ModifyResponse message */
    MODIFY_RESPONSE,
    
    /** The SearchRequest message */
    SEARCH_REQUEST,
    
    /** The SeaechResultDone response message */
    SEARCH_RESULT_DONE,
    
    /** The SearchResultEntry Response message */
    SEARCH_RESULT_ENTRY,
    
    /** The earchResultReference Response message */
    SEARCH_RESULT_REFERENCE,
    
    /** The UnbindRequest message */
    UNBIND_REQUEST,
    
    /** The IntermediateResponse message */
    INTERMEDIATE_RESPONSE;
}
