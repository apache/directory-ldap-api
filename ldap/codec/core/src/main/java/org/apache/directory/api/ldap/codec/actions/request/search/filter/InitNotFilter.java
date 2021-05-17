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
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.search.Filter;
import org.apache.directory.api.ldap.codec.search.NotFilter;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the NOT filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitNotFilter extends GrammarAction<LdapMessageContainer<SearchRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitNotFilter.class );

    /**
     * Instantiates a new init NOT filter action.
     */
    public InitNotFilter()
    {
        super( "Initialize NOT filter" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchRequest> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05136_EMPTY_NOT_FILTER_PDU );
            LOG.error( msg );
            throw new DecoderException( msg );
        }

        // We can allocate the SearchRequest
        Filter notFilter = new NotFilter( tlv.getId() );

        // Set the filter
        container.addCurrentFilter( notFilter );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05149_INITIALIZE_NOT_FILTER ) );
        }
    }
}
