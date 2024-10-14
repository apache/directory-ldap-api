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
package org.apache.directory.api.ldap.codec.actions.request.search;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchResultDoneImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.DnFactory;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the SearchRequest base object
 * <pre>
 * SearchRequest ::= [APPLICATION 3] SEQUENCE {
 *     baseObject LDAPDN,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreSearchRequestBaseObject extends GrammarAction<LdapMessageContainer<SearchRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreSearchRequestBaseObject.class );


    /**
     * Instantiates a new action.
     */
    public StoreSearchRequestBaseObject()
    {
        super( "Store SearchRequest object Name" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchRequest> container ) throws DecoderException
    {
        SearchRequest searchRequest = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // We have to check that this is a correct Dn
        // We have to handle the special case of a 0 length base
        // object,
        // which means that the search is done from the default
        // root.
        if ( tlv.getLength() != 0 )
        {
            byte[] dnBytes = tlv.getValue().getData();
            String dnStr = Strings.utf8ToString( dnBytes );

            try
            {
                DnFactory dnFactory = container.getDnFactory();
                Dn baseObject;

                if ( dnFactory == null )
                {
                    baseObject = new Dn( dnStr );
                }
                else
                {
                    baseObject = dnFactory.create( dnStr );
                }
                
                searchRequest.setBase( baseObject );
            }
            catch ( LdapInvalidDnException ine )
            {
                String msg = I18n.err( I18n.ERR_05132_INVALID_ROOT_DN, dnStr, Strings.dumpBytes( dnBytes ) );
                LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, ine.getMessage() ) );

                SearchResultDoneImpl response = new SearchResultDoneImpl( searchRequest.getMessageId() );
                throw new ResponseCarryingException( msg, response, ResultCodeEnum.INVALID_DN_SYNTAX,
                    Dn.EMPTY_DN, ine );
            }
        }
        else
        {
            searchRequest.setBase( Dn.EMPTY_DN );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05160_SEARCHING_WITH_ROOT_DN, searchRequest.getBase() ) );
        }
    }
}
