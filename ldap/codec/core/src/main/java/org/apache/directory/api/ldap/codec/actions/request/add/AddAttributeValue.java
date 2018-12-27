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


import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to store a Value to an AddRequest
 * <pre>
 * AttributeList ::= SEQUENCE OF SEQUENCE {
 *     ...
 *     vals SET OF AttributeValue }
 *
 * AttributeValue OCTET STRING
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AddAttributeValue extends GrammarAction<LdapMessageContainerDirect<AddRequest>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( AddAttributeValue.class );

    /**
     * Instantiates a new value action.
     */
    public AddAttributeValue()
    {
        super( "Store a value" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainerDirect<AddRequest> container )
    {
        Attribute currentAttribute = container.getCurrentAttribute();

        TLV tlv = container.getCurrentTLV();

        // Store the value. It can't be null
        Object value = null;

        try
        {
            if ( tlv.getLength() == 0 )
            {
                currentAttribute.add( "" );
            }
            else
            {
                if ( container.isBinary( currentAttribute.getId() ) )
                {
                    value = tlv.getValue().getData();

                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.msg( I18n.MSG_05112_ADDING_VALUE, Strings.dumpBytes( ( byte[] ) value ) ) );
                    }

                    currentAttribute.add( ( byte[] ) value );
                }
                else
                {
                    value = Strings.utf8ToString( tlv.getValue().getData() );

                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.msg( I18n.MSG_05112_ADDING_VALUE, value ) );
                    }

                    currentAttribute.add( ( String ) value );
                }
            }
        }
        catch ( LdapException le )
        {
            // Just swallow the exception, it can't occur here
        }

        // We can have an END transition
        container.setGrammarEndAllowed( true );
    }
}
