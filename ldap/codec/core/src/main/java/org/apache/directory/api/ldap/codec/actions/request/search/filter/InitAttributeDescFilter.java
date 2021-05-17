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
package org.apache.directory.api.ldap.codec.actions.request.search.filter;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.AttributeValueAssertion;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.search.AttributeValueAssertionFilter;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the AttributeDesc filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitAttributeDescFilter extends GrammarAction<LdapMessageContainer<SearchRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitAttributeDescFilter.class );

    /**
     * Instantiates a new init attribute desc filter action.
     */
    public InitAttributeDescFilter()
    {
        super( "Initialize AttributeDesc filter" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchRequest> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        AttributeValueAssertion assertion = new AttributeValueAssertion();

        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05135_EMPTY_ATTRIBUTE_DESCRIPTION );
            LOG.error( msg );
            throw new DecoderException( msg );
        }
        else
        {
            String type = Strings.utf8ToString( tlv.getValue().getData() );
            assertion.setAttributeDesc( type );

            AttributeValueAssertionFilter terminalFilter = ( AttributeValueAssertionFilter )
                container.getTerminalFilter();
            terminalFilter.setAssertion( assertion );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05143_INITIALIZE_ATT_DESC_FILTER ) );
        }
    }
}
