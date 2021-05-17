/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequest;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIRequestImpl;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponse;
import org.apache.directory.api.ldap.extras.extended.whoAmI.WhoAmIResponseImpl;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link ExtendedOperationFactory} for creating WhoAmI extended request response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIFactory extends AbstractExtendedOperationFactory
{
    /** logger */
    private static final Logger LOG = LoggerFactory.getLogger( WhoAmIFactory.class );
    
    /**
     * Creates a new instance of WhoAmIFactory.
     *
     * @param codec The codec for this factory.
     */
    public WhoAmIFactory( LdapApiService codec )
    {
        super( codec, WhoAmIRequest.EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIRequest newRequest()
    {
        return new WhoAmIRequestImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIRequest newRequest( byte[] value ) throws DecoderException
    {
        WhoAmIRequest whoAmIRequest = new WhoAmIRequestImpl();

        if ( value != null )
        {
            decodeValue( whoAmIRequest, value );
        }

        return whoAmIRequest;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIResponse newResponse() throws DecoderException
    {
        return new WhoAmIResponseImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public WhoAmIResponse newResponse( byte[] value ) throws DecoderException
    {
        WhoAmIResponse whoAmIResponse = new WhoAmIResponseImpl();

        if ( value != null )
        {
            decodeValue( whoAmIResponse, value );
        }

        return whoAmIResponse;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void encodeValue( Asn1Buffer buffer, ExtendedResponse extendedResponse )
    {
        if ( extendedResponse == null )
        {
            return;
        }

        // Reset the responseName, it should always be null for a WhoAMI extended operation
        extendedResponse.setResponseName( null );
        
        // The authzID as a opaque byte array
        byte[] authzid =  ( ( WhoAmIResponse ) extendedResponse ).getAuthzId();
        
        if ( !Strings.isEmpty( authzid ) )
        {
            buffer.put( authzid );
        }
    }
    
    
    /**
     * Decode a PDU which must contain a WhoAmIResponse extended operation.
     * Note that the stream of bytes much contain a full PDU, not a partial one.
     * 
     * @param whoAmIResponse The WhoAmI extended response that will be feed
     * @param data The bytes to be decoded
     * @return a WhoAmIRequest object
     * @throws org.apache.directory.api.asn1.DecoderException If the decoding failed
     */
    public static WhoAmIResponse decode( WhoAmIResponse whoAmIResponse, byte[] data ) throws DecoderException
    {
        if ( Strings.isEmpty( data ) )
        {
            ( ( WhoAmIResponseImpl ) whoAmIResponse ).setAuthzId( null );
        }
        else
        {
            switch ( data.length )
            {
                case 0:
                    // Error
                case 1:
                    // Error
                    String msg = I18n.err( I18n.ERR_08226_AUTHZID_TOO_SHORT_MISSING_U_OR_DN );
                    LOG.error( msg );
                    throw new DecoderException( msg );

                case 2 :
                    if ( ( data[0] == 'u' ) && ( data[1] == ':' ) )
                    {
                        ( ( WhoAmIResponseImpl ) whoAmIResponse ).setAuthzId( data );
                        ( ( WhoAmIResponseImpl ) whoAmIResponse ).setUserId( Strings.utf8ToString( data, 2, data.length - 2 ) );
                    }
                    else
                    {
                        msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                        LOG.error( msg );
                        throw new DecoderException( msg );
                    }
                    
                    break;
                    
                default :
                    switch ( data[0] )
                    {
                        case 'u' :
                            if ( data[1] == ':' )
                            {
                                ( ( WhoAmIResponseImpl ) whoAmIResponse ).setAuthzId( data );
                                ( ( WhoAmIResponseImpl ) whoAmIResponse ).setUserId( Strings.utf8ToString( data, 2, data.length - 2 ) );
                            }
                            else
                            {
                                msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }
                            
                            break;
                            
                        case 'd' :
                            if ( ( data[1] == 'n' ) && ( data[2] == ':' ) )
                            {
                                // Check that the remaining bytes are a valid DN
                                if ( Dn.isValid( Strings.utf8ToString( data, 3, data.length - 3 ) ) )
                                {
                                    ( ( WhoAmIResponseImpl ) whoAmIResponse ).setAuthzId( data );
                                    
                                    try
                                    {
                                        ( ( WhoAmIResponseImpl ) whoAmIResponse ).setDn( new Dn( Strings.utf8ToString( data, 3, data.length - 3 ) ) );
                                    }
                                    catch ( LdapInvalidDnException e )
                                    {
                                        // Should never happen
                                    }
                                }
                                else
                                {
                                    msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                    LOG.error( msg );
                                    throw new DecoderException( msg );
                                }
                            }
                            else
                            {
                                msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                                LOG.error( msg );
                                throw new DecoderException( msg );
                            }
                            
                            break;

                        default :
                            msg = I18n.err( I18n.ERR_08227_AUTHZID_MUST_START_WITH_U_OR_DN, Strings.utf8ToString( data ) );
                            LOG.error( msg );
                            throw new DecoderException( msg );
                    }
                    
                    break;
            }
        }

        return whoAmIResponse;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void decodeValue( ExtendedResponse extendedResponse, byte[] responseValue ) throws DecoderException
    {
        decode( ( WhoAmIResponse ) extendedResponse, responseValue );
    }
}
