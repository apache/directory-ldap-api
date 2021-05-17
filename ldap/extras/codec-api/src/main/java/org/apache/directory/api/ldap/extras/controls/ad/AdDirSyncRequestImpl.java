/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
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

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;
import org.apache.directory.api.util.Strings;

/**
 * The class implementing the AdDirsSync interface
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncRequestImpl extends AbstractControl implements AdDirSyncRequest
{
    /** The parentsFirst value */
    private int parentsFirst;

    /** The maximum attribute count to return */
    private int maxAttributeCount = 0;

    /** The DirSync cookie */
    private byte[] cookie;

    /**
     * Creates an instance of the DirSync control
     */
    public AdDirSyncRequestImpl()
    {
        super( OID, Boolean.TRUE );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getParentsFirst()
    {
        return parentsFirst;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setParentsFirst( int parentsFirst )
    {
        this.parentsFirst = parentsFirst;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxAttributeCount()
    {
        return maxAttributeCount;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setMaxAttributeCount( int maxAttributeCount )
    {
        this.maxAttributeCount = maxAttributeCount;
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
        int h = super.hashCode();

        h = h * 17 + parentsFirst;
        h = h * 17 + maxAttributeCount;

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
    public boolean equals( Object other )
    {
        if ( this == other )
        {
            return true;
        }

        if ( !( other instanceof AdDirSyncRequest ) )
        {
            return false;
        }

        AdDirSyncRequest otherControl = ( AdDirSyncRequest ) other;

        return super.equals( other )
            && ( maxAttributeCount == otherControl.getMaxAttributeCount() )
            && ( parentsFirst == otherControl.getParentsFirst() )
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
        sb.append( "        parentsFirst : " ).append( parentsFirst ).append( "\n" );
        sb.append( "        maxAttributeCount : '" ).append( maxAttributeCount ).append( "'\n" );
        sb.append( "        cookie            : '" ).append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );

        return sb.toString();
    }
}
