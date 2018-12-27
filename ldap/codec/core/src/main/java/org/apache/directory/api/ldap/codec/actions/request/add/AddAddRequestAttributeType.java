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
package org.apache.directory.api.ldap.codec.actions.request.add;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store the AddRequest AttributeDescription
 * <pre>
 * AttributeList ::= SEQUENCE OF SEQUENCE {
 *     type    AttributeDescription,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddAddRequestAttributeType extends GrammarAction<LdapMessageContainerDirect<AddRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddAddRequestAttributeType.class );

    /**
     * Instantiates a new action.
     */
    public AddAddRequestAttributeType()
    {
        super( "Store attribute type" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainerDirect<AddRequest> container ) throws DecoderException
    {
        AddRequest addRequest = container.getMessage();

        TLV tlv = container.getCurrentTLV();

        // Store the type. It can't be null.
        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_05111_NULL_OR_EMPTY_TYPE_NOT_ALLOWED );
            LOG.error( msg );

            AddResponseImpl response = new AddResponseImpl( addRequest.getMessageId() );

            throw new ResponseCarryingException( msg, response, ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX,
                addRequest.getEntry().getDn(), null );
        }

        String type = Strings.utf8ToString( tlv.getValue().getData() );

        try
        {
            Attribute attribute = addRequest.getEntry().get( type );
            
            if ( attribute == null )
            {
                attribute = new DefaultAttribute( type );
                addRequest.getEntry().add( attribute );
            }
            
            container.setCurrentAttribute( attribute );
        }
        catch ( LdapException ne )
        {
            String msg = I18n.err( I18n.ERR_05112_ERROR_WITH_ATTRIBUTE_TYPE );
            LOG.error( msg );

            AddResponseImpl response = new AddResponseImpl( addRequest.getMessageId() );
            throw new ResponseCarryingException( msg, response, ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX,
                addRequest.getEntry().getDn(), ne );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05111_ADDING_TYPE, type ) );
        }
    }
}
