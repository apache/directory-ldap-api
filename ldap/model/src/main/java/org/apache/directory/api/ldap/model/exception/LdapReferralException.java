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
package org.apache.directory.api.ldap.model.exception;


import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.exception.NotImplementedException;


/**
 * A {@link LdapOperationException} which associates a resultCode namely the
 * {@link org.apache.directory.api.ldap.model.message.ResultCodeEnum#REFERRAL} resultCode with the exception.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapReferralException extends AbstractLdapReferralException
{
    /** The serial version UUID */
    static final long serialVersionUID = 1L;

    /** The list of referrals */
    private final List<String> refs;

    /** The current index in the list of referrals */
    private int index = 0;

    /** The remaining Dn */
    private Dn remainingDn;

    /** The Entry the referral refers to */
    private Object resolvedObject;


    /**
     * 
     * Creates a new instance of LdapReferralException.
     *
     * @param refs The list of referrals
     */
    public LdapReferralException( Collection<String> refs )
    {
        super( null );
        this.refs = new ArrayList<>( refs );
    }


    /**
     * 
     * Creates a new instance of LdapReferralException.
     *
     * @param refs The list of referrals
     * @param explanation The associated error message
     */
    public LdapReferralException( Collection<String> refs, String explanation )
    {
        super( explanation );
        this.refs = new ArrayList<>( refs );
    }


    /**
     * Always returns {@link ResultCodeEnum#REFERRAL}
     * 
     * @return The ResultCode
     */
    @Override
    public ResultCodeEnum getResultCode()
    {
        return ResultCodeEnum.REFERRAL;
    }


    /**
     * @return The current Referral
     */
    public String getReferralInfo()
    {
        return refs.get( index );
    }


    @Override
    public Context getReferralContext() throws NamingException
    {
        throw new NotImplementedException();
    }


    @Override
    public Context getReferralContext( Map<?, ?> arg ) throws NamingException
    {
        throw new NotImplementedException();
    }


    /**
     * Move to the next referral
     * @return true if there is some next referral
     */
    public boolean skipReferral()
    {
        index++;
        return index < refs.size();
    }


    @Override
    public void retryReferral()
    {
        throw new NotImplementedException();
    }


    /**
     * @return the remainingDn
     */
    @Override
    public Dn getRemainingDn()
    {
        return remainingDn;
    }


    /**
     * @param remainingDn the remainingName to set
     */
    @Override
    public void setRemainingDn( Dn remainingDn )
    {
        this.remainingDn = remainingDn;
    }


    /**
     * @return the resolvedObject
     */
    @Override
    public Object getResolvedObject()
    {
        return resolvedObject;
    }


    /**
     * @param resolvedObject the resolvedObject to set
     */
    @Override
    public void setResolvedObject( Object resolvedObject )
    {
        this.resolvedObject = resolvedObject;
    }
}
