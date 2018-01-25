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


import org.apache.directory.api.ldap.model.message.controls.AbstractControl;


/**
 * Implementation of the AD PolicyHints control.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdPolicyHintsImpl extends AbstractControl implements AdPolicyHints
{
    /** This control OID */
    private int flags;

    /**
     * Creates an instance of AdPolicyHintsImpl
     */
    public AdPolicyHintsImpl()
    {
        super( OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getFlags()
    {
        return flags;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setFlags( int flags )
    {
        this.flags = flags;
    }
    
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = 37;

        h = h * 17 + super.hashCode();
        h = h * 17 + flags;

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

        if ( !( o instanceof AdPolicyHints ) )
        {
            return false;
        }

        AdPolicyHints otherControl = ( AdPolicyHints ) o;

        return super.equals( o ) && flags == otherControl.getFlags();
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    AdPolicyHints control :\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        sb.append( "        flags : 0x" ).append( Integer.toHexString( flags ) ).append( "\n" );

        return sb.toString();
    }
}