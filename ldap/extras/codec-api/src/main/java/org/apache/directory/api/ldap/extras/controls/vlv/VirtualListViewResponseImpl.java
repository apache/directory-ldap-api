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

package org.apache.directory.api.ldap.extras.controls.vlv;


import java.util.Arrays;

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;
import org.apache.directory.api.util.Strings;


/**
 * Virtual List View response control as specified in draft-ietf-ldapext-ldapv3-vlv-09.
 * 
 *  VirtualListViewResponse ::= SEQUENCE {
 *         targetPosition    INTEGER (0 .. maxInt),
 *         contentCount     INTEGER (0 .. maxInt),
 *         virtualListViewResult ENUMERATED {
 *              success (0),
 *              operationsError (1),
 *              protocolError (3),
 *              unwillingToPerform (53),
 *              insufficientAccessRights (50),
 *              timeLimitExceeded (3),
 *              adminLimitExceeded (11),
 *              innapropriateMatching (18),
 *              sortControlMissing (60),
 *              offsetRangeError (61),
 *              other(80),
 *              ... },
 *         contextID     OCTET STRING OPTIONAL }
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewResponseImpl extends AbstractControl implements VirtualListViewResponse
{

    private int targetPosition;
    private int contentCount;
    private VirtualListViewResultCode virtualListViewResult;
    private byte[] contextId;


    /**
     * Creates a new VirtualListViewResponseImpl instance
     */
    public VirtualListViewResponseImpl()
    {
        super( OID );
    }


    @Override
    public int getTargetPosition()
    {
        return targetPosition;
    }


    @Override
    public void setTargetPosition( int targetPosition )
    {
        this.targetPosition = targetPosition;
    }


    @Override
    public int getContentCount()
    {
        return contentCount;
    }


    @Override
    public void setContentCount( int contentCount )
    {
        this.contentCount = contentCount;
    }


    @Override
    public VirtualListViewResultCode getVirtualListViewResult()
    {
        return virtualListViewResult;
    }


    @Override
    public void setVirtualListViewResult( VirtualListViewResultCode virtualListViewResultCode )
    {
        this.virtualListViewResult = virtualListViewResultCode;
    }


    @Override
    public byte[] getContextId()
    {
        return contextId;
    }


    @Override
    public void setContextId( byte[] contextId )
    {
        this.contextId = contextId;
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = super.hashCode();

        h = h * 37 + targetPosition;
        h = h * 37 + contentCount;
        h = h * 37 + ( ( virtualListViewResult == null ) ? 0 : virtualListViewResult.hashCode() );

        if ( contextId != null )
        {
            for ( byte b : contextId )
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
        if ( !super.equals( o ) )
        {
            return false;
        }

        VirtualListViewResponseImpl otherControl = ( VirtualListViewResponseImpl ) o;

        return ( targetPosition == otherControl.getTargetPosition() )
            && ( contentCount == otherControl.getContentCount() )
            && ( virtualListViewResult == otherControl.getVirtualListViewResult() )
            && Arrays.equals( contextId, otherControl.getContextId() );
    }


    /**
     * Return a String representing this VirtualListViewResponseImpl.
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Virtual List View Response Control\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        sb.append( "        targetPosition   : '" ).append( targetPosition ).append( "'\n" );
        sb.append( "        contentCount   : '" ).append( contentCount ).append( "'\n" );
        sb.append( "        virtualListViewResult   : '" ).append( virtualListViewResult ).append( "'\n" );

        if ( contextId != null )
        {
            sb.append( "        contextID   : '" ).append( Strings.dumpBytes( contextId ) ).append( "'\n" );
        }

        return sb.toString();
    }
}
