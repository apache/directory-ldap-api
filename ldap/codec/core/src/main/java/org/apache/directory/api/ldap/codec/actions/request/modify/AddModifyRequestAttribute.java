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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the ModificationRequest's attribute type
 * <pre>
 * ModifyRequest ::= [APPLICATION 6] SEQUENCE {
 *     ...
 *     modification SEQUENCE OF SEQUENCE {
 *             ...
 *         modification   AttributeTypeAndValues }
 *
 * AttributeTypeAndValues ::= SEQUENCE {
 *     type AttributeDescription,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddModifyRequestAttribute extends GrammarAction<LdapMessageContainer<ModifyRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddModifyRequestAttribute.class );

    /**
     * Instantiates a new action.
     */
    public AddModifyRequestAttribute()
    {
        super( "Store Modify request operation type" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<ModifyRequest> container ) throws DecoderException
    {
        ModifyRequest modifyRequest = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // Store the value. It can't be null
        String type;

        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05123_TYPE_CANT_BE_NULL );
            LOG.error( msg );

            ModifyResponseImpl response = new ModifyResponseImpl( modifyRequest.getMessageId() );
            throw new ResponseCarryingException( msg, response, ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX,
                modifyRequest.getName(), null );
        }
        else
        {
            type = Strings.utf8ToString( tlv.getValue().getData() );
            Attribute currentAttribute = new DefaultAttribute( type );
            
            container.setCurrentAttribute( currentAttribute );
            container.getCurrentModification().setAttribute( currentAttribute );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05128_MODIFYING_TYPE, type ) );
        }
    }
}
