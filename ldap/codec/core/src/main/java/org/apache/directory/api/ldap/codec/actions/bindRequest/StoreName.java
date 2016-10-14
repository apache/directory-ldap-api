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
package org.apache.directory.api.ldap.codec.actions.bindRequest;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.BindRequestDecorator;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the BindRequest name.
 * <pre>
 * BindRequest ::= [APPLICATION 0] SEQUENCE {
 *     ....
 *     name                    LDAPDN,
 *     ....
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreName extends GrammarAction<LdapMessageContainer<BindRequestDecorator>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreName.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();


    /**
     * Instantiates a new action.
     */
    public StoreName()
    {
        super( "Store BindRequest Name value" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<BindRequestDecorator> container ) throws DecoderException
    {
        BindRequest bindRequestMessage = container.getMessage();

        // Get the Value and store it in the BindRequest
        TLV tlv = container.getCurrentTLV();

        // We have to handle the special case of a 0 length name
        if ( tlv.getLength() == 0 )
        {
            bindRequestMessage.setName( "" );
        }
        else
        {
            byte[] nameBytes = tlv.getValue().getData();
            String nameStr = Strings.utf8ToString( nameBytes );
            bindRequestMessage.setName( nameStr );
        }

        if ( IS_DEBUG )
        {
            LOG.debug( " The Bind name is {}", bindRequestMessage.getName() );
        }
    }
}
