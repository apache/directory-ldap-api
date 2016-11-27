/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.ppolicy;


/**
 * A simple {@link PasswordPolicy} Control implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PasswordPolicyImpl implements PasswordPolicy
{
    /** The criticality of this {@link Control} */
    private boolean criticality;

    /** The password policy response component if this is a response control */
    private PasswordPolicyResponse response;


    /**
     * Creates a new instance of a PasswordPolicy request Control without any
     * response data associated with it.
     */
    public PasswordPolicyImpl()
    {
        response = null;
    }


    /**
     * Creates a new instance of a PasswordPolicy request Control without any
     * response data associated with it.
     * 
     * @param hasResponse A flag set to <tt>true</tt> if the control should have a response
     */
    public PasswordPolicyImpl( boolean hasResponse )
    {
        if ( hasResponse )
        {
            response = new PasswordPolicyResponseImpl();
        }
        else
        {
            response = null;
        }
    }


    /**
     * Creates a new instance of PasswordPolicy response Control with response 
     * information packaged into the control.
     * 
     * @param response The encapsulated response
     */
    public PasswordPolicyImpl( PasswordPolicyResponse response )
    {
        this.response = response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return PasswordPolicy.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCritical()
    {
        return criticality;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCritical( boolean isCritical )
    {
        this.criticality = isCritical;
    }


    /**
     * 
     * {@inheritDoc}
     */
    @Override
    public void setResponse( PasswordPolicyResponse response )
    {
        this.response = response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasResponse()
    {
        return response != null;
    }


    /**
     * 
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyResponse setResponse( boolean hasResponse )
    {
        PasswordPolicyResponse old = this.response;

        if ( hasResponse )
        {
            this.response = new PasswordPolicyResponseImpl();
        }
        else
        {
            this.response = null;
        }

        return old;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public PasswordPolicyResponse getResponse()
    {
        return response;
    }

    
    /**
     * Get a String representation of a PasswordPolicyImpl
     * 
     * @return A BindResponse String
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    PasswordPolicy[" );
        sb.append( "criticality:" ).append( criticality ).append( "] " );

        if ( response != null )
        {
            sb.append( response );
        }
        else
        {
            sb.append( '\n' );
        }

        return sb.toString();
    }
}
