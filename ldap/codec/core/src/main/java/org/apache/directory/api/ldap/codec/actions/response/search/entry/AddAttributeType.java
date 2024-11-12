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
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the SearchResultEntry attributes
 * <pre>
 * SearchResultEntry ::= [APPLICATION 4] SEQUENCE { ...
 *     ...
 *     attributes PartialAttributeList }
 *
 * PartialAttributeList ::= SEQUENCE OF SEQUENCE {
 *     type  AttributeDescription,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddAttributeType extends GrammarAction<LdapMessageContainer<SearchResultEntry>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddAttributeType.class );

    /**
     * Instantiates a new action.
     */
    public AddAttributeType()
    {
        super( "Store the AttributeType" );
    }


    /**
     * {@inheritDoc}
     */
    public void action( LdapMessageContainer<SearchResultEntry> container ) throws DecoderException
    {
        SearchResultEntry searchResultEntry = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // Store the type
        if ( tlv.getLength() == 0 )
        {
            // The type can't be null
            String msg = I18n.err( I18n.ERR_05147_NULL_ATTRIBUTE_TYPE );
            LOG.error( msg );
            throw new DecoderException( msg );
        }
        else
        {
            try
            {
                byte[] attributeTypeBytes = tlv.getValue().getData();
                Attribute attribute = new DefaultAttribute( attributeTypeBytes );
                container.setCurrentAttribute( attribute );

                try
                {
                    searchResultEntry.getEntry().put( attribute );
                }
                catch ( IllegalArgumentException le )
                {
                    String msg = I18n.err( I18n.ERR_05156_INVALID_ATTRIBUTE_TYPE, le.getMessage() );
                    LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, le.getMessage() ) );
                    throw new DecoderException( msg, le );
                }
            }
            catch ( LdapException ine )
            {
                String type = Strings.utf8ToString( tlv.getValue().getData() );
                // This is for the client side. We will never decode LdapResult on the server
                String msg = I18n.err( I18n.ERR_05156_INVALID_ATTRIBUTE_TYPE, type, ine.getMessage() );
                LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg, ine.getMessage() ) );
                throw new DecoderException( msg, ine );
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            String type = Strings.utf8ToString( tlv.getValue().getData() );
            LOG.debug( I18n.msg( I18n.MSG_05179_ATTRIBUTE_TYPE, type ) );
        }
    }
}
