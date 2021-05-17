/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.passwordExpired;

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;

/**
 * A PasswordExpiredResponse control implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PasswordExpiredResponseImpl extends AbstractControl implements PasswordExpiredResponse
{
    /** time before expiration of the password */
    private int timeBeforeExpiration = -1;

    /**
     * Creates a new instance of a PasswordExpired Control without any
     * response data associated with it.
     */
    public PasswordExpiredResponseImpl() 
    {
        super( OID );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeBeforeExpiration()
    {
        return timeBeforeExpiration;
    }

    /**
     * Return a String representing this PasswordExpiredControl.
     */
    @Override
    public String toString() 
    {
        StringBuilder sb = new StringBuilder();
        sb.append( "    Password Expired Response Control\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        
        return sb.toString();
    }
}
