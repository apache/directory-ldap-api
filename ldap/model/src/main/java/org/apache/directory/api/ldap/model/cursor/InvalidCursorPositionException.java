/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.cursor;


/**
 * Thrown to indicate an illegal position state for a Cursor when a call to
 * get is made.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InvalidCursorPositionException extends CursorException
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 5730037129071653272L;


    /**
     * Creates a new instance of InvalidCursorPositionException.
     */
    public InvalidCursorPositionException()
    {
    }


    /**
     * Creates a new instance of InvalidCursorPositionException.
     *
     * @param message The associated message
     */
    public InvalidCursorPositionException( String message )
    {
        super( message );
    }
}
