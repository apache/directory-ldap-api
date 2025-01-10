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
 * A {@link LdapException} which associates a resultCode namely the
 * {@link ResultCodeEnum#OTHER} resultCode with the exception.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapConfigurationException extends LdapOperationException
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 1L;

    /** The exception cause */
    private Throwable cause;


    /**
     * Creates a new instance of LdapConfigurationException.
     *
     * @param message The exception message
     */
    public LdapConfigurationException( String message )
    {
        super( ResultCodeEnum.OTHER, message );
    }


    /**
     * Creates a new instance of LdapConfigurationException.
     */
    public LdapConfigurationException()
    {
        super( ResultCodeEnum.OTHER, null );
    }


    /**
     * Creates a new instance of LdapConfigurationException.
     *
     * @param message the exception message
     * @param cause the cause
     */
    public LdapConfigurationException( String message, Throwable cause )
    {
        super( ResultCodeEnum.OTHER, message );
        this.cause = cause;
    }


    /**
     * @return the exception's cause
     */
    @Override
    public Throwable getCause()
    {
        return cause;
    }


    /**
     * Set the root cause.
     *
     * @param cause the cause
     */
    public void setCause( Throwable cause )
    {
        this.cause = cause;
    }
}
