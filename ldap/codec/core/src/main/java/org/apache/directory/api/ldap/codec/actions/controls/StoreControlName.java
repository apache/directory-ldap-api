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
package org.apache.directory.api.ldap.codec.actions.controls;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.grammar.GrammarAction;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainerDirect;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Request;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used add a new control. We store its OID.
 * <pre>
 * Control ::= SEQUENCE {
 *     controlType             LDAPOID,
 *     ...LdapMessageContainerDirect<Message>
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoreControlName extends GrammarAction<LdapMessageContainerDirect<Message>>
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( StoreControlName.class );

    /**
     * Instantiates a new AddControl action.
     */
    public StoreControlName()
    {
        super( "Add a new control" );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void action( LdapMessageContainerDirect<Message> container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        // Store the type
        // We have to handle the special case of a 0 length OID
        if ( tlv.getLength() == 0 )
        {
            String msg = I18n.err( I18n.ERR_08214_NULL_OID );
            LOG.error( msg );

            // This will generate a PROTOCOL_ERROR
            throw new DecoderException( msg );
        }

        byte[] value = tlv.getValue().getData();
        String oidValue = Strings.asciiBytesToString( value );

        // The OID is encoded as a String, not an Object Id
        if ( !Oid.isOid( oidValue ) )
        {
            String msg = I18n.err( I18n.ERR_08215_INVALID_CONTROL_OID, oidValue );
            LOG.error( msg );

            // This will generate a PROTOCOL_ERROR
            throw new DecoderException( msg );
        }

        // Search for the control. It can be a request or a response control.
        // If the control is not known, we create an Opaque control
        Message message = container.getMessage();
        LdapApiService codec = container.getLdapCodecService();
        ControlFactory<? extends Control> controlFactory;
        
        Control control;

        if ( message instanceof Request )
        {
            controlFactory = codec.getRequestControlFactories().get( oidValue );
        }
        else
        {
            controlFactory = codec.getResponseControlFactories().get( oidValue );
        }

        if ( controlFactory == null )
        {
            control =  new OpaqueControl( oidValue );
        }
        else
        {
            control = controlFactory.newControl();
        }

        container.setControlFactory( controlFactory );
        
        // At this point, the control exists, we may have to decode the value and feed it
        //In any case, add it to the message's controls, and store it in the container for further
        // processing (aka, value decoding)
        message.addControl( control );

        container.setCurrentControl( control );

        // We can have an END transition
        container.setGrammarEndAllowed( true );

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_08201_CONTROL_OID, oidValue ) );
        }
    }
}
