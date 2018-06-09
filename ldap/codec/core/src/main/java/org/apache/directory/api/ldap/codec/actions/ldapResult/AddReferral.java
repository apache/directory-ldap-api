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
package org.apache.directory.api.ldap.codec.actions.ldapResult;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to add a referral to a LdapTresult
 * <pre>
 * Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI (RFC 4511)
 * URI ::= LDAPString
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddReferral extends GrammarAction<LdapMessageContainer<MessageDecorator<? extends Message>>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddReferral.class );


    /**
     * Instantiates a new referral action.
     */
    public AddReferral()
    {
        super( "Add a referral" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<MessageDecorator<? extends Message>> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        Message response = container.getMessage();
        LdapResult ldapResult = ( ( ResultResponse ) response ).getLdapResult();
        Referral referral = ldapResult.getReferral();

        if ( tlv.getLength() == 0 )
        {
            referral.addLdapUrl( "" );
        }
        else
        {
            if ( ldapResult.getResultCode() == ResultCodeEnum.REFERRAL )
            {
                try
                {
                    String url = Strings.utf8ToString( tlv.getValue().getData() );
                    referral.addLdapUrl( new LdapUrl( url ).toString() );
                }
                catch ( LdapURLEncodingException luee )
                {
                    String badUrl = Strings.utf8ToString( tlv.getValue().getData() );
                    LOG.error( I18n.err( I18n.ERR_05103_INVALID_URL, badUrl, luee.getMessage() ) );
                    throw new DecoderException( I18n.err( I18n.ERR_05104_INVALID_URL, luee.getMessage() ), luee );
                }
            }
            else
            {
                if ( LOG.isWarnEnabled() )
                {
                    LOG.warn( I18n.msg( I18n.MSG_05103_REFERRAL_ERROR_MESSAGE_NOT_ALLOWED ) );
                }
                
                referral.addLdapUrl( LdapUrl.EMPTY_URL.toString() );
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            StringBuilder sb = new StringBuilder();
            boolean isFirst = true;

            for ( String url : ldapResult.getReferral().getLdapUrls() )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sb.append( ", " );
                }

                sb.append( url );
            }

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_05104_REFERRAL_ERROR_MESSAGE_SET_TO, sb.toString() ) );
             }
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );
    }
}
