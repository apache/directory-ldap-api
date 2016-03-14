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
package org.apache.directory.api.ldap.model.name;


import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;


/**
 * This exception is used to signal that the complex parser should be used.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TooComplexDnException extends LdapInvalidDnException
{
    // The defualt serila version ID
    private static final long serialVersionUID = 4854240181901296414L;
    
    /** An instance of this exception to avoid creation a new one every time we need it */
    public static final TooComplexDnException INSTANCE = new TooComplexDnException();

    /**
     * Creates a new instance of TooComplexException.
     */
    public TooComplexDnException()
    {
        super( ( String ) null );
    }


    /**
     * Creates a new instance of TooComplexException.
     * 
     * @param message The associated message 
     */
    public TooComplexDnException( String message )
    {
        super( message );
    }
}
