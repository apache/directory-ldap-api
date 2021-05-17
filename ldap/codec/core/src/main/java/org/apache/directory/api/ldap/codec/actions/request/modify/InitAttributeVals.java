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
package org.apache.directory.api.ldap.codec.actions.request.modify;


import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the set of ModificationRequest AVAs
 * <pre>
 * ModifyRequest ::= [APPLICATION 6] SEQUENCE {
 *     ...
 *     modification SEQUENCE OF SEQUENCE {
 *             ...
 *         modification   AttributeTypeAndValues }
 *
 * AttributeTypeAndValues ::= SEQUENCE {
 *     ...
 *     vals SET OF AttributeValue }
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitAttributeVals extends GrammarAction<LdapMessageContainer<ModifyRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitAttributeVals.class );


    /**
     * Instantiates a new action.
     */
    public InitAttributeVals()
    {
        super( "Init Attribute vals" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<ModifyRequest> container )
    {
        TLV tlv = container.getCurrentTLV();

        // If the length is null, we store an empty value
        if ( LOG.isDebugEnabled() && ( tlv.getLength() == 0 ) )
        {
            LOG.debug( I18n.msg( I18n.MSG_05129_NO_VALS_FOR_ATTRIBUTE ) );
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05130_SOME_VALS_NEED_DECODING ) );
        }
    }
}
