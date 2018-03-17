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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.directory.api.ldap.model.message.IntermediateResponseImpl;
import org.apache.directory.api.util.Strings;


/**
 * A simple {@link SyncInfoValue} implementation to store response properties.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SyncInfoValueImpl extends IntermediateResponseImpl implements SyncInfoValue
{
    /** The kind of syncInfoValue we are dealing with */
    private SynchronizationInfoEnum type;

    /** The cookie */
    private byte[] cookie;

    /** The refreshDone flag if we are dealing with refreshXXX syncInfo. Default to true */
    private boolean refreshDone = true;

    /** The refreshDeletes flag if we are dealing with syncIdSet syncInfo. Defaults to false */
    private boolean refreshDeletes = false;

    /** The list of UUIDs if we are dealing with syncIdSet syncInfo */
    private List<byte[]> syncUUIDs;


    /**
     * Creates a new instance of SyncInfoValueImpl.
     */
    public SyncInfoValueImpl()
    {
        super( OID );
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
        this.cookie = cookie;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRefreshDone()
    {
        return refreshDone;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRefreshDone( boolean refreshDone )
    {
        this.refreshDone = refreshDone;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isRefreshDeletes()
    {
        return refreshDeletes;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRefreshDeletes( boolean refreshDeletes )
    {
        this.refreshDeletes = refreshDeletes;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<byte[]> getSyncUUIDs()
    {
        return syncUUIDs;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setSyncUUIDs( List<byte[]> syncUUIDs )
    {
        this.syncUUIDs = syncUUIDs;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addSyncUUID( byte[] syncUUID )
    {
        if ( syncUUIDs == null )
        {
            syncUUIDs = new ArrayList<>();
        }

        syncUUIDs.add( syncUUID );
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = super.hashCode();

        h = h * 17 + type.getValue();
        h = h * 17 + ( refreshDone ? 1 : 0 );
        h = h * 17 + ( refreshDeletes ? 1 : 0 );

        if ( cookie != null )
        {
            for ( byte b : cookie )
            {
                h = h * 17 + b;
            }
        }

        if ( syncUUIDs != null )
        {
            for ( byte[] bytes : syncUUIDs )
            {
                if ( bytes != null )
                {
                    for ( byte b : bytes )
                    {
                        h = h * 17 + b;
                    }
                }
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

        if ( !( o instanceof SyncInfoValue ) )
        {
            return false;
        }

        SyncInfoValue otherResponse = ( SyncInfoValue ) o;

        if ( syncUUIDs != null )
        {
            if ( otherResponse.getSyncUUIDs() == null )
            {
                return false;
            }

            // @TODO : this is extremely heavy... We have to find a better way to
            // compare the lists of suncUuids, but atm, it's enough.
            for ( byte[] syncUuid : syncUUIDs )
            {
                boolean found = false;

                for ( byte[] otherSyncUuid : otherResponse.getSyncUUIDs() )
                {
                    if ( Arrays.equals( syncUuid, otherSyncUuid ) )
                    {
                        found = true;
                        break;
                    }
                }

                if ( !found )
                {
                    return false;
                }
            }
        }
        else
        {
            if ( otherResponse.getSyncUUIDs() != null )
            {
                return false;
            }
        }

        return super.equals( o )
            && ( refreshDeletes == otherResponse.isRefreshDeletes() )
            && ( refreshDone == otherResponse.isRefreshDone() )
            && ( Arrays.equals( cookie, otherResponse.getCookie() ) );
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    SyncInfoValue :\n" );

        switch ( type )
        {
            case NEW_COOKIE:
                sb.append( "        newCookie : '" ).
                    append( Strings.utf8ToString( getCookie() ) ).append( "'\n" );
                break;

            case REFRESH_DELETE:
                sb.append( "        refreshDelete : \n" );

                if ( getCookie() != null )
                {
                    sb.append( "            cookie : '" ).
                        append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );
                }

                sb.append( "            refreshDone : " ).append( isRefreshDone() ).append( '\n' );
                break;

            case REFRESH_PRESENT:
                sb.append( "        refreshPresent : \n" );

                if ( getCookie() != null )
                {
                    sb.append( "            cookie : '" ).
                        append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );
                }

                sb.append( "            refreshDone : " ).append( isRefreshDone() ).append( '\n' );
                break;

            case SYNC_ID_SET:
                sb.append( "        syncIdSet : \n" );

                if ( getCookie() != null )
                {
                    sb.append( "            cookie : '" ).
                        append( Strings.dumpBytes( getCookie() ) ).append( "'\n" );
                }

                sb.append( "            refreshDeletes : " ).append( isRefreshDeletes() ).append( '\n' );
                sb.append( "            syncUUIDS : " );

                if ( !getSyncUUIDs().isEmpty() )
                {
                    boolean isFirst = true;

                    for ( byte[] syncUUID : getSyncUUIDs() )
                    {
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            sb.append( ", " );
                        }

                        sb.append( Arrays.toString( syncUUID ) );
                    }

                    sb.append( '\n' );
                }
                else
                {
                    sb.append( "empty\n" );
                }

                break;

            default:
                throw new IllegalArgumentException( "Unexpected SynchronizationInfo: " + getType() );
        }

        return sb.toString();
    }


    @Override
    public SynchronizationInfoEnum getSyncInfoValueType()
    {
        return type;
    }


    @Override
    public void setSyncInfoValueType( SynchronizationInfoEnum type )
    {
        this.type = type;
    }
}
