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
package org.apache.directory.ldap.client.api;


/**
 * An LdapConnection validator intended to be used by a GenericObjectPool to
 * determine whether or not a conneciton is still <i>usable</i>.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapConnectionValidator
{
    /**
     * Return true if the connection is still valid.  This means that if this
     * connections is handed out to a user, it <i>should</i> allow for 
     * successful communication with the server.
     *
     * @param ldapConnection The connection to test
     * @return True, if the connection is still valid
     */
    boolean validate( LdapConnection ldapConnection );
}
