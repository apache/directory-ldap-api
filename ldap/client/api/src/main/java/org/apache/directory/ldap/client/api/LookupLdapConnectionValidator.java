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
package org.apache.directory.ldap.client.api;


import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * An implementation of {@link LdapConnectionValidator} that attempts a simple
 * lookup on the rootDSE.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LookupLdapConnectionValidator implements LdapConnectionValidator
{
    /**
     * Default constructor
     */
     public LookupLdapConnectionValidator()
     {
         // nothing to do
     }
     
     
    /**
     * Returns true if <code>connection</code> is connected, authenticated, and
     * a lookup on the rootDSE returns a non-null response.
     * 
     * @param connection The connection to validate
     * @return True, if the connection is still valid
     */
    @Override
    public boolean validate( LdapConnection connection )
    {
        try
        {
            return connection.isConnected()
                && connection.isAuthenticated()
                && ( connection.lookup( Dn.ROOT_DSE, SchemaConstants.NO_ATTRIBUTE ) != null );
        }
        catch ( LdapException e )
        {
            return false;
        }
    }
}
