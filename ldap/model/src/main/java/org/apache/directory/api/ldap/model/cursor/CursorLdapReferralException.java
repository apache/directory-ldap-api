/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.cursor;


import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * A specific form of CursorException used when a referral is met
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CursorLdapReferralException extends CursorException
{
    /** The serialVersion UID */
    private static final long serialVersionUID = -5723233489761854394L;

    /** A static exception to be used by the monitor */
    public static final CursorLdapReferralException INSTANCE = new CursorLdapReferralException( null );

    /** The contained referralException */
    private LdapReferralException ldapReferralException;


    /**
     * Creates a new instance of CursorClosedException.
     * 
     * @param ldapReferralException The associated exception
     */
    public CursorLdapReferralException( LdapReferralException ldapReferralException )
    {
        this.ldapReferralException = ldapReferralException;
    }


    /**
     * Creates a new instance of CursorClosedException.
     *
     * @param ldapReferralException The associated exception
     * @param message The associated message
     */
    public CursorLdapReferralException( LdapReferralException ldapReferralException, String message )
    {
        super( message );

        this.ldapReferralException = ldapReferralException;
    }


    /**
     * Creates a new instance of CursorClosedException.
     *
     * @param ldapReferralException The associated exception
     * @param message The associated message
     * @param cause The original cause
     */
    public CursorLdapReferralException( LdapReferralException ldapReferralException, String message, Throwable cause )
    {
        super( message, cause );

        this.ldapReferralException = ldapReferralException;
    }


    /**
     * Always returns {@link ResultCodeEnum#REFERRAL}
     * 
     * @see LdapReferralException#getResultCode()
     * 
     * @return the underlying LdapReferral result code, if any
     */
    public ResultCodeEnum getResultCode()
    {
        if ( ldapReferralException != null )
        {
            return ldapReferralException.getResultCode();
        }
        else
        {
            return ResultCodeEnum.UNKNOWN;
        }
    }


    /**
     * @return The current Referral
     */
    public String getReferralInfo()
    {
        if ( ldapReferralException != null )
        {
            return ldapReferralException.getReferralInfo();
        }
        else
        {
            return "";
        }
    }


    /**
     * Move to the next referral
     * 
     * @return true if there is some next referral
     */
    public boolean skipReferral()
    {
        if ( ldapReferralException != null )
        {
            return ldapReferralException.skipReferral();
        }
        else
        {
            return false;
        }
    }


    /**
     * @return the remainingDn
     */
    public Dn getRemainingDn()
    {
        if ( ldapReferralException != null )
        {
            return ldapReferralException.getRemainingDn();
        }
        else
        {
            return Dn.EMPTY_DN;
        }
    }


    /**
     * @return the resolvedObject
     */
    public Object getResolvedObject()
    {
        if ( ldapReferralException != null )
        {
            return ldapReferralException.getResolvedObject();
        }
        else
        {
            return null;
        }
    }
}
