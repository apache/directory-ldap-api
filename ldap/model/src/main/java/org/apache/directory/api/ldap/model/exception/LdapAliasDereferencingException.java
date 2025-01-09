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
 * A subclass of {@link LdapOperationException} which associates the
 * {@link org.apache.directory.api.ldap.model.message.ResultCodeEnum#ALIAS_DEREFERENCING_PROBLEM} value with the type.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapAliasDereferencingException extends LdapOperationException
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1L;


    /**
     * Creates a new instance of LdapAliasDereferencingException.
     *
     * @param message The exception message
     */
    public LdapAliasDereferencingException( String message )
    {
        super( ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM, message );
    }


    /**
     * Creates a new instance of LdapAliasDereferencingException.
     */
    public LdapAliasDereferencingException()
    {
        super( ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM, null );
    }
}
