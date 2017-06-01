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

package org.apache.directory.api.ldap.extras.controls.ad;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;
import org.apache.directory.api.util.Strings;

/**
 * The class implemnting the AdDirsSync interface
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncImpl extends AbstractControl implements AdDirSync
{
    /** Flags used to control return values (client-to-server) or indicate that there are more data to return (server-to-client) */
    private Set<AdDirSyncFlag> flags = EnumSet.noneOf( AdDirSyncFlag.class );
     

    /** The maximum number of attributes to return */
    private int maxReturnLength = 0;
    
    /** The DirSync cookie */
    private byte[] cookie;

    /**
     * Creates an instance of the DirSync control
     */
    public AdDirSyncImpl()
    {
        super( OID, Boolean.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<AdDirSyncFlag> getFlags()
    {
        return flags;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setFlags( Set<AdDirSyncFlag> flags )
    {
        this.flags = flags;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addFlag( AdDirSyncFlag flag )
    {
        flags.add( flag );
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public void removeFlag( AdDirSyncFlag flag )
    {
        flags.remove( flag );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxReturnLength()
    {
        return maxReturnLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setMaxReturnLength( int maxReturnLength )
    {
        this.maxReturnLength = maxReturnLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getCookie()
    {
        return cookie;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCookie( byte[] cookie )
    {
        if ( cookie != null )
        {
            this.cookie = new byte[cookie.length];
            System.arraycopy( cookie, 0, this.cookie, 0, cookie.length );
        }
        else
        {
            this.cookie = Strings.EMPTY_BYTES;
        }
    }
    
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = 37;

        h = h * 17 + super.hashCode();
        h = h * 17 + AdDirSyncFlag.getBitmask( flags );
        h = h * 17 + maxReturnLength;

        if ( cookie != null )
        {
            for ( byte b : cookie )
            {
                h = h * 17 + b;
            }
        }

        return h;
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }

        if ( !( o instanceof AdDirSync ) )
        {
            return false;
        }

        AdDirSync otherControl = ( AdDirSync ) o;

        return ( maxReturnLength == otherControl.getMaxReturnLength() )
            && ( flags.equals( otherControl.getFlags() ) )
            && ( Arrays.equals( cookie, otherControl.getCookie() ) )
            && ( isCritical() == otherControl.isCritical() );
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    DirSync control :\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        sb.append( "        flags : 0x" ).append( Integer.toHexString( AdDirSyncFlag.getBitmask( flags ) ) )
                    .append( ' ' ).append( flags.toString() ).append( "\n" );
        sb.append( "        maxReturnLength : '" ).append( getMaxReturnLength() ).append( "'\n" );
        sb.append( "        cookie            : '" ).append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );

        return sb.toString();
    }
}
