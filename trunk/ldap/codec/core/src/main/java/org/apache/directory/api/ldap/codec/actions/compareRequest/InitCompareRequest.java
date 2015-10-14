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
package org.apache.directory.api.ldap.codec.actions.compareRequest;


import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.CompareRequestDecorator;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareRequestImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the CompareRequest.
 * <pre>
 * LdapMessage ::= ... CompareRequest ...
 *
 * CompareRequest ::= [APPLICATION 14] SEQUENCE {
 * ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitCompareRequest extends GrammarAction<LdapMessageContainer<CompareRequestDecorator>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitCompareRequest.class );


    /**
     * Instantiates a new action.
     */
    public InitCompareRequest()
    {
        super( "Compare Request initialization" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<CompareRequestDecorator> container )
    {
        // Now, we can allocate the CompareRequest Object
        CompareRequest internalCompareRequest = new CompareRequestImpl();
        internalCompareRequest.setMessageId( container.getMessageId() );
        CompareRequestDecorator compareRequest = new CompareRequestDecorator(
            container.getLdapCodecService(), internalCompareRequest );
        container.setMessage( compareRequest );

        LOG.debug( "Compare Request" );
    }
}
