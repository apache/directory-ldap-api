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
package org.apache.directory.api.ldap.codec.actions.request.search.filter;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.codec.search.Filter;
import org.apache.directory.api.ldap.codec.search.OrFilter;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the OR filter
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitOrFilter extends GrammarAction<LdapMessageContainerDirect<SearchRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitOrFilter.class );

    /**
     * Instantiates a new init OR filter action.
     */
    public InitOrFilter()
    {
        super( "Initialize OR filter" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainerDirect<SearchRequest> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05137_EMPTY_OR_FILTER_PDU );
            LOG.error( msg );
            throw new DecoderException( msg );
        }

        // We can allocate the SearchRequest
        Filter orFilter = new OrFilter( tlv.getId() );

        // Set the filter
        container.addCurrentFilter( orFilter );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05150_INITIALIZE_OR_FILTER ) );
        }
    }
}
