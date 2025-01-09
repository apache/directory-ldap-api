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
package org.apache.directory.ldap.client.api.exception;


import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * A InvalidConnectionException is thrown if one tries to apply an operation
 * on a closed connection
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InvalidConnectionException extends LdapException
{
    /** Declares the Serial Version Uid */
    static final long serialVersionUID = 1L;


    /**
     * Instantiates a new invalid connection exception.
     */
    public InvalidConnectionException()
    {
        super();
    }


    /**
     * Instantiates a new invalid connection exception.
     *
     * @param explanation the explanation
     */
    public InvalidConnectionException( String explanation )
    {
        super( explanation );
    }


    /**
     * Instantiates a new invalid connection exception.
     *
     * @param explanation the explanation
     * @param cause The root cause for this exception
     */
    public InvalidConnectionException( String explanation, Throwable cause )
    {
        super( explanation, cause );
    }
}
