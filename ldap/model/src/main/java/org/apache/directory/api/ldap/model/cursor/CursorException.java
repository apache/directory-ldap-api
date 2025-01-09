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
package org.apache.directory.api.ldap.model.cursor;


/**
 * An class for exceptions which add Cursor specific information to
 * Exceptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CursorException extends Exception
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 1L;


    /**
     * Creates a new instance of CursorException.
     */
    public CursorException()
    {
    }


    /**
     * Creates a new instance of CursorException.
     *
     * @param explanation The message associated with the exception
     */
    public CursorException( String explanation )
    {
        super( explanation );
    }


    /**
     * Creates a new instance of LdapException.
     * 
     * @param cause The root cause for this exception
     */
    public CursorException( Throwable cause )
    {
        super( cause );
    }


    /**
     * Creates a new instance of CursorException.
     *
     * @param explanation The message associated with the exception
     * @param cause The root cause for this exception
     */
    public CursorException( String explanation, Throwable cause )
    {
        super( explanation, cause );
    }
}
