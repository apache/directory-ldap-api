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
package org.apache.directory.api.dsmlv2.response;


import java.util.Collection;
import java.util.List;

import org.apache.directory.api.dsmlv2.DsmlDecorator;
import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.dom4j.Element;


/**
 * DSML Decorator for the LdapResult class.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapResultDsml implements DsmlDecorator<LdapResult>, LdapResult
{
    /** The LDAP Result to decorate */
    private LdapResult result;

    /** The associated LDAP Message */
    private Message message;

    /** The ldap codec service */
    private LdapApiService codec;


    /**
     * Creates a new instance of LdapResultDsml.
     *
     * @param codec The LDAP Service to use
     * @param result the LdapResult to decorate
     * @param message the associated message
     */
    public LdapResultDsml( LdapApiService codec, LdapResult result, Message message )
    {
        this.codec = codec;
        this.result = result;
        this.message = message;
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {

        // RequestID
        int requestID = message.getMessageId();
        if ( requestID > 0 )
        {
            root.addAttribute( "requestID", Integer.toString( requestID ) );
        }

        // Matched Dn
        Dn matchedDn = result.getMatchedDn();

        if ( !Dn.isNullOrEmpty( matchedDn ) )
        {
            root.addAttribute( "matchedDn", matchedDn.getName() );
        }

        // Controls
        ParserUtils.addControls( codec, root, message.getControls().values() );

        // ResultCode
        Element resultCodeElement = root.addElement( "resultCode" );
        resultCodeElement.addAttribute( "code", Integer.toString( result.getResultCode().getResultCode() ) );
        resultCodeElement.addAttribute( "descr", result.getResultCode().getMessage() );

        // ErrorMessage
        String errorMessage = ( result.getDiagnosticMessage() );
        
        if ( ( errorMessage != null ) && ( errorMessage.length() != 0 ) )
        {
            Element errorMessageElement = root.addElement( "errorMessage" );
            errorMessageElement.addText( errorMessage );
        }

        // Referrals
        Referral referral = result.getReferral();
        if ( referral != null )
        {
            Collection<String> ldapUrls = referral.getLdapUrls();
            if ( ldapUrls != null )
            {
                for ( String ldapUrl : ldapUrls )
                {
                    Element referalElement = root.addElement( "referal" );
                    referalElement.addText( ldapUrl );
                }
            }
        }

        return root;
    }


    /**
     * {@inheritDoc}
     */
    public String getDiagnosticMessage()
    {
        return result.getDiagnosticMessage();
    }


    /**
     * {@inheritDoc}
     */
    public void setDiagnosticMessage( String diagnosticMessage )
    {
        result.setDiagnosticMessage( diagnosticMessage );
    }


    /**
     * Get the matched Dn
     * 
     * @return Returns the matchedDN.
     */
    public Dn getMatchedDn()
    {
        return result.getMatchedDn();
    }


    /**
     * Set the Matched Dn
     * 
     * @param matchedDn The matchedDn to set.
     */
    public void setMatchedDn( Dn matchedDn )
    {
        result.setMatchedDn( matchedDn );
    }


    /**
     * Get the referrals
     * 
     * @return Returns the referrals.
     */
    public List<String> getReferrals()
    {
        return ( List<String> ) result.getReferral().getLdapUrls();
    }


    /**
     * Add a referral
     * 
     * @param referral The referral to add.
     */
    public void addReferral( LdapUrl referral )
    {
        result.getReferral().addLdapUrl( referral.toString() );
    }


    /**
     * Get the result code
     * 
     * @return Returns the resultCode.
     */
    public ResultCodeEnum getResultCode()
    {
        return result.getResultCode();
    }


    /**
     * Set the result code
     * 
     * @param resultCode The resultCode to set.
     */
    public void setResultCode( ResultCodeEnum resultCode )
    {
        result.setResultCode( resultCode );
    }


    /**
     * {@inheritDoc}
     */
    public LdapResult getDecorated()
    {
        return result;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isReferral()
    {
        return getDecorated().isReferral();
    }


    /**
     * {@inheritDoc}
     */
    public Referral getReferral()
    {
        return getDecorated().getReferral();
    }


    /**
     * {@inheritDoc}
     */
    public void setReferral( Referral referral )
    {
        getDecorated().setReferral( referral );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isDefaultSuccess()
    {
        return false;
    }
}
