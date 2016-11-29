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
package org.apache.directory.api.ldap.model.message;


import java.util.Arrays;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Bind protocol operation request which authenticates and begins a client
 * session. Does not yet contain interfaces for SASL authentication mechanisms.
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public class BindRequestImpl extends AbstractAbandonableRequest implements BindRequest
{

    /** A logger */
    private static final Logger LOG = LoggerFactory.getLogger( BindRequestImpl.class );

    /**
     * Distinguished name identifying the name of the authenticating subject -
     * defaults to the empty string
     */
    private Dn dn;

    /**
     * String identifying the name of the authenticating subject -
     * defaults to the empty string
     */
    private String name;

    /** The passwords, keys or tickets used to verify user identity */
    private byte[] credentials;

    /** A storage for credentials hashCode */
    private int hCredentials;

    /** The mechanism used to decode user identity */
    private String mechanism;

    /** Simple vs. SASL authentication mode flag */
    private boolean isSimple = true;

    /** Bind behavior exhibited by protocol version */
    private boolean isVersion3 = true;

    /** The associated response */
    private BindResponse response;


    // ------------------------------------------------------------------------
    // Constructors
    // ------------------------------------------------------------------------
    /**
     * Creates an BindRequest implementation to bind to an LDAP server.
     */
    public BindRequestImpl()
    {
        super( -1, MessageTypeEnum.BIND_REQUEST );
        hCredentials = 0;
    }


    // -----------------------------------------------------------------------
    // BindRequest Interface Method Implementations
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSimple()
    {
        return isSimple;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getSimple()
    {
        return isSimple;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setSimple( boolean simple )
    {
        this.isSimple = simple;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getCredentials()
    {
        return credentials;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setCredentials( String credentials )
    {
        return setCredentials( Strings.getBytesUtf8( credentials ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setCredentials( byte[] credentials )
    {
        if ( credentials != null )
        {
            this.credentials = new byte[credentials.length];
            System.arraycopy( credentials, 0, this.credentials, 0, credentials.length );
        }
        else
        {
            this.credentials = null;
        }

        // Compute the hashcode
        if ( credentials != null )
        {
            hCredentials = 0;

            for ( byte b : credentials )
            {
                hCredentials = hCredentials * 31 + b;
            }
        }
        else
        {
            hCredentials = 0;
        }

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getSaslMechanism()
    {
        return mechanism;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setSaslMechanism( String saslMechanism )
    {
        this.isSimple = false;
        this.mechanism = saslMechanism;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getName()
    {
        return name;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setName( String name )
    {
        this.name = name;

        try
        {
            this.dn = new Dn( name );
        }
        catch ( LdapInvalidDnException e )
        {
            // This might still be a valid DN (Windows AD binding for instance)
            LOG.debug( "Unable to convert the name to a DN." );
            this.dn = null;
        }

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getDn()
    {
        return dn;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setDn( Dn dn )
    {
        this.dn = dn;
        this.name = dn.getName();

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVersion3()
    {
        return isVersion3;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean getVersion3()
    {
        return isVersion3;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setVersion3( boolean version3 )
    {
        this.isVersion3 = version3;

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest addControl( Control control )
    {
        return ( BindRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest addAllControls( Control[] controls )
    {
        return ( BindRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public BindRequest removeControl( Control control )
    {
        return ( BindRequest ) super.removeControl( control );
    }


    // -----------------------------------------------------------------------
    // BindRequest Interface Method Implementations
    // -----------------------------------------------------------------------
    /**
     * Gets the protocol response message type for this request which produces
     * at least one response.
     * 
     * @return the message type of the response.
     */
    @Override
    public MessageTypeEnum getResponseType()
    {
        return MessageTypeEnum.BIND_RESPONSE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    @Override
    public BindResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new BindResponseImpl( getMessageId() );
        }

        return response;
    }


    /**
     * RFC 2251/4511 [Section 4.11]: Abandon, Bind, Unbind, and StartTLS operations
     * cannot be abandoned.
     */
    @Override
    public void abandon()
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_04185 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( ( obj == null ) || !( obj instanceof BindRequest ) )
        {
            return false;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        BindRequest req = ( BindRequest ) obj;

        if ( req.isSimple() != isSimple() )
        {
            return false;
        }

        if ( req.isVersion3() != isVersion3() )
        {
            return false;
        }

        String name1 = req.getName();
        String name2 = getName();

        if ( Strings.isEmpty( name1 ) )
        {
            if ( !Strings.isEmpty( name2 ) )
            {
                return false;
            }
        }
        else
        {
            if ( Strings.isEmpty( name2 ) )
            {
                return false;
            }
            else if ( !name2.equals( name1 ) )
            {
                return false;
            }
        }

        Dn dn1 = req.getDn();
        Dn dn2 = getDn();

        if ( Dn.isNullOrEmpty( dn1 ) )
        {
            if ( !Dn.isNullOrEmpty( dn2 ) )
            {
                return false;
            }
        }
        else
        {
            if ( Dn.isNullOrEmpty( dn2 ) )
            {
                return false;
            }
            else if ( !dn1.equals( dn2 ) )
            {
                return false;
            }
        }

        return Arrays.equals( req.getCredentials(), getCredentials() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        hash = hash * 17 + ( credentials == null ? 0 : hCredentials );
        hash = hash * 17 + ( isSimple ? 0 : 1 );
        hash = hash * 17 + ( isVersion3 ? 0 : 1 );
        hash = hash * 17 + ( mechanism == null ? 0 : mechanism.hashCode() );
        hash = hash * 17 + ( name == null ? 0 : name.hashCode() );
        hash = hash * 17 + ( response == null ? 0 : response.hashCode() );
        hash = hash * 17 + super.hashCode();

        return hash;
    }


    /**
     * Get a String representation of a BindRequest
     * 
     * @return A BindRequest String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    BindRequest\n" );
        sb.append( "        Version : '" ).append( isVersion3 ? "3" : "2" ).append( "'\n" );

        if ( ( ( Strings.isEmpty( name ) ) || ( dn == null ) || Strings.isEmpty( dn.getNormName() ) )
            && isSimple )
        {
            sb.append( "        Name : anonymous\n" );
        }
        else
        {
            sb.append( "        Name : '" ).append( name ).append( "'\n" );

            if ( isSimple )
            {
                sb.append( "        Simple authentication : '" ).append( "(omitted-for-safety)" ).append( "'\n" );
            }
            else
            {
                sb.append( "        Sasl credentials\n" );
                sb.append( "            Mechanism :'" ).append( mechanism ).append( "'\n" );

                if ( credentials == null )
                {
                    sb.append( "            Credentials : null" );
                }
                else
                {
                    sb.append( "            Credentials : (omitted-for-safety)" );
                }
            }
        }

        // The controls if any
        return super.toString( sb.toString() );
    }
}
