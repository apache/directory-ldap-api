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
package org.apache.directory.api.ldap.extras.extended.whoAmI;


import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * The RFC 4532 WhoAmI response :
 * 
 * <pre>
 * authzid OCTET STRING OPTIONAL
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIResponseImpl extends ExtendedResponseImpl implements WhoAmIResponse
{
    /** The authzid */
    private byte[] authzId;
    
    /** The authzId when it's a DN */
    private Dn dn;
    
    /** The authzId when it's a userId */
    private String userId;

    
    /**
     * Create a new instance for the WhoAmI response
     * @param messageId The Message ID
     * @param rcode The result code
     * @param diagnosticMessage The diagnostic message
     */
    public WhoAmIResponseImpl( int messageId, ResultCodeEnum rcode, String diagnosticMessage )
    {
        super( messageId, EXTENSION_OID );

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
        super.getLdapResult().setDiagnosticMessage( diagnosticMessage );
    }


    /**
     * Create a new instance for the WhoAmI response
     * @param messageId The Message ID
     * @param rcode The result code
     */
    public WhoAmIResponseImpl( int messageId, ResultCodeEnum rcode )
    {
        super( messageId, EXTENSION_OID );

        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( rcode );
    }


    /**
     * Instantiates a new WhoAmI response.
     *
     * @param messageId the message id
     */
    public WhoAmIResponseImpl( int messageId )
    {
        super( messageId, EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * Instantiates a new WhoAmI response.
     */
    public WhoAmIResponseImpl()
    {
        super( EXTENSION_OID );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getAuthzId()
    {
        return authzId;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setAuthzId( byte[] authzId )
    {
        this.authzId = authzId;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDnAuthzId()
    {
        return dn != null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isUserAuthzId()
    {
        return userId != null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getAuthzIdString()
    {
        return Strings.utf8ToString( authzId );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getUserId()
    {
        return userId;
    }


    /**
     * Set the userId
     * 
     * @param userId The User ID
     */
    public void setUserId( String userId )
    {
        this.userId = userId;
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
     * Set the DN
     * 
     * @param dn The DN to set
     */
    public void setDn( Dn dn )
    {
        this.dn = dn;
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "WhoAmI Extended Response :" );
        sb.append( "\n    authzid : " );

        if ( authzId != null )
        {
            if ( isDnAuthzId() )
            {
                sb.append( "DN: " ).append( getDn() );
            }
            else
            {
                sb.append( "UserId: " ).append( getUserId() );
            }
        }
        else
        {
            sb.append( "null" );
        }

        return sb.toString();
    }
}
