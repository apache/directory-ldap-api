/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.message.controls;


import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;


/**
 * Simple ProxiedAuthz implementation class.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class ProxiedAuthzImpl extends AbstractControl implements ProxiedAuthz
{
    /**
     * The authzId used to authorize the user.
     */
    private String authzId;


    /**
     * Default constructor.
     */
    public ProxiedAuthzImpl()
    {
        super( OID );

        // The criticality must be true
        setCritical( true );
    }


    /**
     * @return the authzId
     */
    @Override
    public String getAuthzId()
    {
        return authzId;
    }


    /**
     * The authzId syntax is given by the RFC 2829 :
     * 
     * <pre>
     * authzId    = dnAuthzId / uAuthzId / &lt;empty&gt;
     * dnAuthzId  = "dn:" dn
     * dn         = utf8string
     * uAuthzId   = "u:" userid
     * userid     = utf8string
     * </pre>
     * @param authzId the authzId to set
     */
    @Override
    public void setAuthzId( String authzId )
    {
        // We should have a valid authzId
        if ( authzId == null )
        {
            throw new RuntimeException( "Invalid proxied authz value : cannot be null" );
        }

        if ( !Strings.isEmpty( authzId ) )
        {
            String lowercaseAuthzId = Strings.toLowerCaseAscii( authzId );

            if ( lowercaseAuthzId.startsWith( "dn:" ) )
            {
                String dn = authzId.substring( 3 );

                if ( !Dn.isValid( dn ) )
                {
                    throw new RuntimeException( "Invalid proxied authz value : the DN is not valid" );
                }
            }
            else if ( !lowercaseAuthzId.startsWith( "u:" ) )
            {
                throw new RuntimeException( "Invalid proxied authz value : should start with 'dn:' or 'u:'" );
            }
        }

        this.authzId = authzId;
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = super.hashCode();

        if ( authzId != null )
        {
            h = h * 37 + authzId.hashCode();
        }

        return h;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        ProxiedAuthz otherControl = ( ProxiedAuthz ) o;

        return ( authzId == otherControl.getAuthzId() )
            || ( ( authzId != null ) && authzId.equals( otherControl.getAuthzId() ) );
    }


    /**
     * Return a String representing this PagedSearchControl.
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Proxied Authz Control\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        sb.append( "        authzid   : '" ).append( authzId ).append( "'\n" );

        return sb.toString();
    }
}