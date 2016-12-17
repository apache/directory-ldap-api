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
public class AbstractLdapReferralException extends LdapOperationException
{
    /** The serial version UUID */
    static final long serialVersionUID = 1L;

    /** The remaining Dn */
    private Dn remainingDn;

    /** The entry the referal refers to */
    private Object resolvedObject;


    /**
     * 
     * Creates a new instance of AbstractLdapReferralException.
     *
     * @param explanation The associated message
     */
    public AbstractLdapReferralException( String explanation )
    {
        super( explanation );
    }


    /**
     * Always returns {@link ResultCodeEnum#REFERRAL}
     * 
     * @return The interned ResultCode
     */
    @Override
    public ResultCodeEnum getResultCode()
    {
        return ResultCodeEnum.REFERRAL;
    }


    /**
     * Not yet implemented
     * 
     * @return The Referral Context
     * @throws NamingException If the operation failed
     */
    public Context getReferralContext() throws NamingException
    {
        throw new NotImplementedException();
    }


    /**
     * Not yet implemented
     * 
     * @param arg The arguments
     * @return The referral context
     * @throws NamingException If the operation failed
     */
    public Context getReferralContext( Map<?, ?> arg ) throws NamingException
    {
        throw new NotImplementedException();
    }


    /**
     * Retry. Not yet implemented
     */
    public void retryReferral()
    {
        throw new NotImplementedException();
    }


    /**
     * @return the remainingDn
     */
    public Dn getRemainingDn()
    {
        return remainingDn;
    }


    /**
     * @param remainingDn the remainingName to set
     */
    public void setRemainingDn( Dn remainingDn )
    {
        this.remainingDn = remainingDn;
    }


    /**
     * @return the resolvedObject
     */
    public Object getResolvedObject()
    {
        return resolvedObject;
    }


    /**
     * @param resolvedObject the resolvedObject to set
     */
    public void setResolvedObject( Object resolvedObject )
    {
        this.resolvedObject = resolvedObject;
    }
}
