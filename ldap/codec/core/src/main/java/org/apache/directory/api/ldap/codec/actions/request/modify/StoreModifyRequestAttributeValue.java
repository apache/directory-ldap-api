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
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a Value to an modifyRequest
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreModifyRequestAttributeValue extends GrammarAction<LdapMessageContainer<ModifyRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreModifyRequestAttributeValue.class );

    /**
     * Instantiates a new modify attribute value action.
     */
    public StoreModifyRequestAttributeValue()
    {
        super( "Stores AttributeValue" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<ModifyRequest> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        // Store the value. It can't be null
        byte[] value = Strings.EMPTY_BYTES;
        Attribute currentAttribute = container.getCurrentAttribute();
        
        if ( ( container.getCurrentModification().getOperation() == ModificationOperation.INCREMENT_ATTRIBUTE ) 
             && ( currentAttribute.size() > 0 ) )
        {
            String msg = I18n.err( I18n.ERR_05160_MORE_THAN_ONE_VALUE_INCREMENT_MOD_OP, currentAttribute.getUpId() );
            LOG.error( I18n.err( I18n.ERR_05114_ERROR_MESSAGE, msg ) );

            ModifyResponseImpl response = new ModifyResponseImpl( container.getMessageId() );
            throw new ResponseCarryingException( msg, response, ResultCodeEnum.OPERATIONS_ERROR, container.getMessage().getName(), null );
        }

        try
        {
            if ( tlv.getLength() == 0 )
            {
                currentAttribute.add( "" );
            }
            else
            {
                value = tlv.getValue().getData();

                if ( container.isBinary( currentAttribute.getId() ) )
                {
                    container.getCurrentAttribute().add( value );
                }
                else
                {
                    currentAttribute.add( Strings.utf8ToString( ( byte[] ) value ) );
                }
            }
        }
        catch ( LdapException le )
        {
            // Just swallow the exception, it can't occur here
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05131_VALUE_MODIFIED, value ) );
        }
    }
}
