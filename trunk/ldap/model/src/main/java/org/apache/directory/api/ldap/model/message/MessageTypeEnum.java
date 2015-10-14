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
    ABANDON_REQUEST,
    ADD_REQUEST,
    ADD_RESPONSE,
    BIND_REQUEST,
    BIND_RESPONSE,
    COMPARE_REQUEST,
    COMPARE_RESPONSE,
    DEL_REQUEST,
    DEL_RESPONSE,
    EXTENDED_REQUEST,
    EXTENDED_RESPONSE,
    MODIFYDN_REQUEST,
    MODIFYDN_RESPONSE,
    MODIFY_REQUEST,
    MODIFY_RESPONSE,
    SEARCH_REQUEST,
    SEARCH_RESULT_DONE,
    SEARCH_RESULT_ENTRY,
    SEARCH_RESULT_REFERENCE,
    UNBIND_REQUEST,
    INTERMEDIATE_RESPONSE;
}
