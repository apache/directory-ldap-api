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

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;
import org.apache.directory.api.util.Strings;

/**
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncImpl extends AbstractControl implements AdDirSync
{
    /** A flag used to tell the server to return the parent before the children */
    int parentFirst = 1;
    
    /** The maximum number of attributes to return */
    int maxAttributeCount = 0;
    
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
    public int getParentFirst()
    {
        return parentFirst;
    }

    
    /**
     * {@inheritDoc}
     */
    public void setParentFirst( int parentFirst )
    {
        this.parentFirst = parentFirst;
    }


    /**
     * {@inheritDoc}
     */
    public int getMaxAttributeCount()
    {
        return maxAttributeCount;
    }


    /**
     * {@inheritDoc}
     */
    public void setMaxAttributeCount( int maxAttributeCount )
    {
        this.maxAttributeCount = maxAttributeCount;
    }


    /**
     * {@inheritDoc}
     */
    public byte[] getCookie()
    {
        return cookie;
    }


    /**
     * {@inheritDoc}
     */
    public void setCookie( byte[] cookie )
    {
        this.cookie = cookie;
    }
    
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = 37;

        h = h * 17 + super.hashCode();
        h = h * 17 + parentFirst;
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

        return ( maxAttributeCount == otherControl.getMaxAttributeCount() ) &&
            ( parentFirst == otherControl.getParentFirst() ) &&
            ( Arrays.equals( cookie, otherControl.getCookie() ) &&
            ( isCritical() == otherControl.isCritical() ) );
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
        sb.append( "        parentFirst : '" ).append( getParentFirst() ).append( "'\n" );
        sb.append( "        maxAttributeCount : '" ).append( getMaxAttributeCount() ).append( "'\n" );
        sb.append( "        cookie            : '" ).append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );

        return sb.toString();
    }
}
