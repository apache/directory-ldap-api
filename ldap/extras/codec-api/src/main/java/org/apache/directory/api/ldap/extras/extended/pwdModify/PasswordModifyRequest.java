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


import org.apache.directory.api.ldap.model.message.ExtendedRequest;


/**
 * The RFC 3062 PwdModify request :
 * 
 * <pre>
 *   PasswdModifyRequestValue ::= SEQUENCE {
 *    userIdentity    [0]  OCTET STRING OPTIONAL
 *    oldPasswd       [1]  OCTET STRING OPTIONAL
 *    newPasswd       [2]  OCTET STRING OPTIONAL }
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface PasswordModifyRequest extends ExtendedRequest
{
    /** The OID for the pwdModify extended operation request. */
    String EXTENSION_OID = "1.3.6.1.4.1.4203.1.11.1";


    /**
     * @return the userIdentity
     */
    byte[] getUserIdentity();


    /**
     * Set the user identity
     * 
     * @param userIdentity The userIdentity to set
     */
    void setUserIdentity( byte[] userIdentity );


    /**
     * @return the oldPassword
     */
    byte[] getOldPassword();


    /**
     * Set the old password
     * 
     * @param oldPassword The oldPassword to set
     */
    void setOldPassword( byte[] oldPassword );


    /**
     * @return the newPassword
     */
    byte[] getNewPassword();


    /**
     * Set a new password
     * 
     * @param newPassword The new password to set
     */
    void setNewPassword( byte[] newPassword );
}
