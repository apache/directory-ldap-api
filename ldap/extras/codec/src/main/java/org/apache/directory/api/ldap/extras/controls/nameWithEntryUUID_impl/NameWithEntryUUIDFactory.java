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
package org.apache.directory.api.ldap.extras.controls.nameWithEntryUUID_impl;


import org.apache.directory.api.ldap.codec.api.AbstractControlFactory;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.nameWithEntryUUID.NameWithEntryUUID;
import org.apache.directory.api.ldap.extras.controls.nameWithEntryUUID.NameWithEntryUUIDImpl;


/**
 * A codec {@link ControlFactory} implementation for {@link NameWithEntryUUID} controls.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class NameWithEntryUUIDFactory extends AbstractControlFactory<NameWithEntryUUID>
{
    /**
     * Creates a new instance of NameWithEntryUUIDFactory.
     *
     * @param codec The LDAP codec
     */
    public NameWithEntryUUIDFactory( LdapApiService codec )
    {
        super( codec, NameWithEntryUUID.OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public NameWithEntryUUID newControl()
    {
        return new NameWithEntryUUIDImpl();
    }
}
