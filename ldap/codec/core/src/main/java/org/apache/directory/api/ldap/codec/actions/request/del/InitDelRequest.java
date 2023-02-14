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
package org.apache.directory.api.ldap.codec.actions.request.del;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.ResponseCarryingException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequestImpl;
import org.apache.directory.api.ldap.model.message.DeleteResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.DnFactory;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to initialize the DelRequest.
 * <pre>
 * LdapMessage ::= ... DelRequest ...
 * delRequest ::= [APPLICATION 10] LDAPDN
 *
 * We store the Dn to bve deleted into the DelRequest object
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class InitDelRequest extends GrammarAction<LdapMessageContainer<DeleteRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( InitDelRequest.class );

    /**
     * Instantiates a new action.
     */
    public InitDelRequest()
    {
        super( "Delete Request initialization" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<DeleteRequest> container ) throws DecoderException
    {
        // Create the DeleteRequest LdapMessage instance and store it in the container
        DeleteRequest delRequest = new DeleteRequestImpl();
        delRequest.setMessageId( container.getMessageId() );
        container.setMessage( delRequest );

        // And store the Dn into it
        // Get the Value and store it in the DelRequest
        TLV tlv = container.getCurrentTLV();

        // We have to handle the special case of a 0 length matchedDN
        if ( tlv.getLength() == 0 )
        {
            // This will generate a PROTOCOL_ERROR
            throw new DecoderException( I18n.err( I18n.ERR_05119_NULL_ENTRY ) );
        }
        else
        {
            byte[] dnBytes = tlv.getValue().getData();
            String dnStr = Strings.utf8ToString( dnBytes );

            try
            {
                DnFactory dnFactory = container.getDnFactory();
                Dn entryDn;
                
                if ( dnFactory == null )
                {
                    entryDn = new Dn( dnStr );
                }
                else
                {
                    entryDn = dnFactory.create( dnStr );
                }

                delRequest.setName( entryDn );
            }
            catch ( LdapInvalidDnException ine )
            {
                String msg = I18n.err( I18n.ERR_05120_INVALID_DELETE_DN, dnStr, 
                    Strings.dumpBytes( dnBytes ), ine.getLocalizedMessage() );
                LOG.error( msg );

                DeleteResponseImpl response = new DeleteResponseImpl( delRequest.getMessageId() );
                throw new ResponseCarryingException( msg, response, ResultCodeEnum.INVALID_DN_SYNTAX,
                    Dn.EMPTY_DN, ine );
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05124_DELETING_DN, delRequest.getName() ) );
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );
    }
}
