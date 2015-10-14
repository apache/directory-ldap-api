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
package org.apache.directory.api.ldap.extras.extended.pwdModify;


import org.apache.directory.api.ldap.model.message.ExtendedResponse;


/**
 * The RFC 3062 PwdModify response :
 * 
 * <pre>
 * PasswdModifyResponseValue ::= SEQUENCE {
 *    genPasswd       [0]     OCTET STRING OPTIONAL }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface PasswordModifyResponse extends ExtendedResponse
{
    /** The OID for the PwdModify extended operation response. */
    String EXTENSION_OID = PasswordModifyRequest.EXTENSION_OID;


    /**
     * Get the generated password
     * 
     * @return The generated password or null
     */
    byte[] getGenPassword();
}
