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
package org.apache.directory.api.ldap.model.message.controls;


import java.util.ArrayList;
import java.util.List;


/**
 * Implementation of SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortRequestControlImpl extends AbstractControl implements SortRequest
{
    /**
     * the list of sort keys
     */
    private List<SortKey> sortKeys;


    /**
     * Creates a new SortRequestControlImpl instance
     */
    public SortRequestControlImpl()
    {
        super( OID );
    }


    /**
     * @return the sortKeys
     */
    @Override
    public List<SortKey> getSortKeys()
    {
        return sortKeys;
    }


    /**
     * @param sortKeys the sortKeys to set
     */
    @Override
    public void setSortKeys( List<SortKey> sortKeys )
    {
        this.sortKeys = sortKeys;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addSortKey( SortKey skey )
    {
        if ( sortKeys == null )
        {
            sortKeys = new ArrayList<>();
        }

        sortKeys.add( skey );
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = super.hashCode();
        
        if ( sortKeys != null )
        {
            for ( SortKey sortKey : sortKeys )
            {
                hash = hash * 17 + sortKey.hashCode();
            }
        }
        
        return hash;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }
        
        if ( !( o instanceof SortRequest ) )
        {
            return false;
        }
        
        SortRequest that = ( SortRequest ) o;
        
        if ( !super.equals( o ) )
        {
            return false;
        }
        
        if ( sortKeys == null )
        {
            return that.getSortKeys() == null;
        }
        
        if ( ( that.getSortKeys() == null ) || ( sortKeys.size() != that.getSortKeys().size() ) )
        {
            return false;
        }
        
        for ( SortKey sortKey : that.getSortKeys() )
        {
            if ( !sortKeys.contains( sortKey ) )
            {
                return false;
            }
        }
        
        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Sort Request Control\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        
        if ( sortKeys != null )
        {
            sb.append( "        sortKeys : [" );
            boolean isFirst = true;
            
            for ( SortKey sortKey : sortKeys )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    sb.append( ", " );
                }
                
                sb.append( sortKey.getAttributeTypeDesc() );
            }
            
            sb.append( "]\n" );
        }
        else
        {
            sb.append( "        sortKeys : null\n" );
        }
        
        return sb.toString();
    }
}
