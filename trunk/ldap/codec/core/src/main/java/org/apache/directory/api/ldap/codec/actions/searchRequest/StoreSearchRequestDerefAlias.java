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
package org.apache.directory.api.ldap.codec.actions.searchRequest;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.decorators.SearchRequestDecorator;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the SearchRequest derefAlias flag
 * <pre>
 * SearchRequest ::= [APPLICATION 3] SEQUENCE {
 *     ...
 *     derefAliases ENUMERATED {
 *         neverDerefAliases   (0),
 *         derefInSearching    (1),
 *         derefFindingBaseObj (2),
 *         derefAlways         (3) },
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreSearchRequestDerefAlias extends GrammarAction<LdapMessageContainer<SearchRequestDecorator>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreSearchRequestDerefAlias.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();


    /**
     * Instantiates a new action.
     */
    public StoreSearchRequestDerefAlias()
    {
        super( "Store SearchRequest derefAlias flag" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchRequestDecorator> container ) throws DecoderException
    {
        SearchRequest searchRequest = container.getMessage().getDecorated();

        TLV tlv = container.getCurrentTLV();

        // We have to check that this is a correct derefAliases
        BerValue value = tlv.getValue();
        int derefAliases = 0;

        try
        {
            derefAliases = IntegerDecoder.parse( value, LdapCodecConstants.NEVER_DEREF_ALIASES,
                LdapCodecConstants.DEREF_ALWAYS );
        }
        catch ( IntegerDecoderException ide )
        {
            String msg = I18n.err( I18n.ERR_04102, value.toString() );
            LOG.error( msg );
            throw new DecoderException( msg, ide );
        }

        searchRequest.setDerefAliases( AliasDerefMode.getDerefMode( derefAliases ) );

        if ( IS_DEBUG )
        {
            switch ( derefAliases )
            {
                case LdapCodecConstants.NEVER_DEREF_ALIASES:
                    LOG.debug( "Handling object strategy : NEVER_DEREF_ALIASES" );
                    break;

                case LdapCodecConstants.DEREF_IN_SEARCHING:
                    LOG.debug( "Handling object strategy : DEREF_IN_SEARCHING" );
                    break;

                case LdapCodecConstants.DEREF_FINDING_BASE_OBJ:
                    LOG.debug( "Handling object strategy : DEREF_FINDING_BASE_OBJ" );
                    break;

                case LdapCodecConstants.DEREF_ALWAYS:
                    LOG.debug( "Handling object strategy : DEREF_ALWAYS" );
                    break;

                default:
                    LOG.debug( "Handling object strategy : UNKNOWN" );
            }
        }
    }
}