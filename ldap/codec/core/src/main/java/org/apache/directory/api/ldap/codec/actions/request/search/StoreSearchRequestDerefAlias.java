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
package org.apache.directory.api.ldap.codec.actions.request.search;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoder;
import org.apache.directory.api.asn1.ber.tlv.IntegerDecoderException;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
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
public class StoreSearchRequestDerefAlias extends GrammarAction<LdapMessageContainer<SearchRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreSearchRequestDerefAlias.class );

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
    public void action( LdapMessageContainer<SearchRequest> container ) throws DecoderException
    {
        SearchRequest searchRequest = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // We have to check that this is a correct derefAliases
        BerValue value = tlv.getValue();

        try
        {
            int derefAliases = IntegerDecoder.parse( value, LdapCodecConstants.NEVER_DEREF_ALIASES,
                LdapCodecConstants.DEREF_ALWAYS );
            searchRequest.setDerefAliases( AliasDerefMode.getDerefMode( derefAliases ) );
        }
        catch ( IntegerDecoderException ide )
        {
            String msg = I18n.err( I18n.ERR_05150_BAD_DEREF_ALIAS, value.toString() );
            LOG.error( msg );
            throw new DecoderException( msg, ide );
        }


        if ( LOG.isDebugEnabled() )
        {
            switch ( searchRequest.getDerefAliases() )
            {
                case NEVER_DEREF_ALIASES:
                    LOG.debug( I18n.msg( I18n.MSG_05161_HANDLING_OBJECT_STRATEGY, "NEVER_DEREF_ALIASES" ) );
                    break;

                case DEREF_IN_SEARCHING:
                    LOG.debug( I18n.msg( I18n.MSG_05161_HANDLING_OBJECT_STRATEGY, "DEREF_IN_SEARCHING" ) );
                    break;

                case DEREF_FINDING_BASE_OBJ:
                    LOG.debug( I18n.msg( I18n.MSG_05161_HANDLING_OBJECT_STRATEGY, "DEREF_FINDING_BASE_OBJ" ) );
                    break;

                case DEREF_ALWAYS:
                    LOG.debug( I18n.msg( I18n.MSG_05161_HANDLING_OBJECT_STRATEGY, "DEREF_ALWAYS" ) );
                    break;

                default:
                    LOG.debug( I18n.msg( I18n.MSG_05161_HANDLING_OBJECT_STRATEGY, "UNKNOWN" ) );
            }
        }
    }
}