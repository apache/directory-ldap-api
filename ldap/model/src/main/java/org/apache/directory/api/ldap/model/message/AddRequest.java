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

package org.apache.directory.api.ldap.model.message;


import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * Add protocol operation request used to add a new entry to the DIT.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface AddRequest extends SingleReplyRequest, AbandonableRequest
{
    /**
     * Gets the distinguished name of the entry to add.
     * 
     * @return the Dn of the added entry.
     */
    Dn getEntryDn();


    /**
     * Sets the distinguished name of the entry to add.
     * 
     * @param entry the Dn of the added entry.
     * @return The AddRequest instance
     */
    AddRequest setEntryDn( Dn entry );


    /**
     * Gets the entry to add.
     * 
     * @return the added Entry
     */
    Entry getEntry();


    /**
     * Sets the Entry to add.
     * 
     * @param entry the added Entry
     * @return The AddRequest instance
     */
    AddRequest setEntry( Entry entry );


    /**
     * {@inheritDoc}
     */
    @Override
    AddRequest setMessageId( int messageId );


    /**
     * {@inheritDoc}
     */
    @Override
    AddRequest addControl( Control control );


    /**
     * {@inheritDoc}
     */
    @Override
    AddRequest addAllControls( Control[] controls );


    /**
     * {@inheritDoc}
     */
    @Override
    AddRequest removeControl( Control control );
}
