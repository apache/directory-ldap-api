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
package org.apache.directory.api.ldap.model.exception;


import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * A LdapUnknownException which associates a resultCode, namely the
 * {@link ResultCodeEnum#UNKNOWN} resultCode with the exception.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapUnknownException extends LdapOperationException
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1L;

    /**
     * 
     * Creates a new instance of LdapUnknownException.
     *
     */
    public LdapUnknownException()
    {
        super( ResultCodeEnum.UNKNOWN, null );
    }


    /**
     * 
     * Creates a new instance of LdapUnknownException.
     *
     * @param explanation The associated error message
     */
    public LdapUnknownException( String explanation )
    {
        super( ResultCodeEnum.UNKNOWN, explanation );
    }
}
