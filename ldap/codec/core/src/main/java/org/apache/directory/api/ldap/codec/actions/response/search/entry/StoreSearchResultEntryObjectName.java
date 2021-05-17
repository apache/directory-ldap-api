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
package org.apache.directory.api.ldap.codec.actions.response.search.entry;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the SearchResultEntry name
 * <pre>
 * LdapMessage ::= ... SearchResultEntry ...
 * SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
 *         objectName      LDAPDN,
 *         ...
 *
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreSearchResultEntryObjectName extends GrammarAction<LdapMessageContainer<SearchResultEntry>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreSearchResultEntryObjectName.class );

    /**
     * Instantiates a new action.
     */
    public StoreSearchResultEntryObjectName()
    {
        super( "Store SearchResultEntry name" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchResultEntry> container ) throws DecoderException
    {
        SearchResultEntry searchResultEntry = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // Store the value.
        if ( tlv.getLength() == 0 )
        {
            searchResultEntry.setObjectName( Dn.EMPTY_DN );
        }
        else
        {
            byte[] dnBytes = tlv.getValue().getData();
            String dnStr = Strings.utf8ToString( dnBytes );

            try
            {
                Dn objectName = new Dn( dnStr );
                searchResultEntry.setObjectName( objectName );
            }
            catch ( LdapInvalidDnException ine )
            {
                // This is for the client side. We will never decode LdapResult on the server
                String msg = I18n.err( I18n.ERR_05157_INVALID_DN, Strings.dumpBytes( dnBytes ), ine.getMessage() );
                LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, ine.getMessage() ) );
                throw new DecoderException( msg, ine );
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05182_SEARCH_RESULT_ENTRY_DN, searchResultEntry.getObjectName() ) );
        }
    }
}
