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
package org.apache.directory.api.ldap.codec.actions.ldapResult;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.DnFactory;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to set the LdapResult matched Dn.
 *
 * <pre>
 * LDAPResult ::= SEQUENCE {
 *     ...
 *     matchedDN LDAPDN,
 *     ...
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreMatchedDN extends GrammarAction<LdapMessageContainer<Message>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreMatchedDN.class );

    /**
     * Instantiates a new matched dn action.
     */
    public StoreMatchedDN()
    {
        super( "Store matched Dn" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainer<Message> container ) throws DecoderException
    {
        // Get the Value and store it in the BindResponse
        TLV tlv = container.getCurrentTLV();
        Dn matchedDn;
        ResultCodeEnum resultCode;

        LdapResult ldapResult = container.getLdapResult();
        resultCode = ldapResult.getResultCode();

        // We have to handle the special case of a 0 length matched
        // Dn
        if ( tlv.getLength() == 0 )
        {
            matchedDn = Dn.EMPTY_DN;
        }
        else
        {
            // A not null matchedDn is valid for resultCodes
            // NoSuchObject, AliasProblem, InvalidDNSyntax and
            // AliasDreferencingProblem.

            switch ( resultCode )
            {
                case NO_SUCH_OBJECT:
                case ALIAS_PROBLEM:
                case INVALID_DN_SYNTAX:
                case ALIAS_DEREFERENCING_PROBLEM:
                    byte[] dnBytes = tlv.getValue().getData();
                    String dnStr = Strings.utf8ToString( dnBytes );

                    try
                    {
                        DnFactory dnFactory = container.getDnFactory();
                        
                        if ( dnFactory == null )
                        {
                            matchedDn = new Dn( dnStr );
                        }
                        else
                        {
                            matchedDn = dnFactory.create( dnStr );
                        }
                    }
                    catch ( LdapInvalidDnException ine )
                    {
                        // This is for the client side. We will never decode LdapResult on the server
                        String msg = I18n.err( I18n.ERR_05106_INCORRECT_DN_GIVEN_INVALID, dnStr, Strings.dumpBytes( dnBytes ), ine
                            .getLocalizedMessage() );
                        LOG.error( msg );

                        throw new DecoderException( I18n.err( I18n.ERR_05107_INCORRECT_DN_GIVEN, ine.getLocalizedMessage() ), ine );
                    }

                    break;

                default:
                    if ( LOG.isWarnEnabled() )
                    {
                        LOG.warn( I18n.msg( I18n.MSG_05107_NO_SUCH_OBJECT_MATCHED_DN_NOT_SET ) );
                    }

                    matchedDn = Dn.EMPTY_DN;
                    break;
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_05108_MATCHED_DN_IS, matchedDn ) );
        }

        ldapResult.setMatchedDn( matchedDn );
    }
}
