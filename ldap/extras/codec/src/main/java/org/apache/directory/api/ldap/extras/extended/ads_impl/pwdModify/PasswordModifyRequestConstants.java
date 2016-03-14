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
package org.apache.directory.api.ldap.extras.extended.ads_impl.pwdModify;


/**
 * PasswordModifyRequest extended operation constants
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class PasswordModifyRequestConstants
{
    /** This is the TAG used for the userIdentity. It's a contextual primitive Tag */
    public static final int USER_IDENTITY_TAG = 0x80;

    /** This is the TAG used for the userIdentity. It's a contextual primitive Tag */
    public static final int OLD_PASSWORD_TAG = 0x81;

    /** This is the TAG used for the userIdentity. It's a contextual primitive Tag */
    public static final int NEW_PASSWORD_TAG = 0x82;


    /**
     * Private constructor.
     */
    private PasswordModifyRequestConstants()
    {
    }
}
