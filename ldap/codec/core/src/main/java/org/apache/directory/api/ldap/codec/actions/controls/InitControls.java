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
package org.apache.directory.api.ldap.codec.actions.controls;


import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialise the controls.
 * <pre>
 *         ... },
 *     controls       [0] Controls OPTIONAL }
 *     
 * Controls ::= SEQUENCE OF control Control

 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitControls extends GrammarAction<LdapMessageContainer<Message>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitControls.class );

    /**
     * Instantiates a new controls init action.
     */
    public InitControls()
    {
        super( "Initialize a control" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<Message> container )
    {
        TLV tlv = container.getCurrentTLV();
        int expectedLength = tlv.getLength();

        // The Length can be null
        if ( expectedLength != 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_05100_NEW_LIST_CONTROLS_INITIALIZED ) );
            }
        }
        else
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_05101_NEW_EMPTY_CONTROLS_INITIALIZED ) );
            }
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );
    }
}
