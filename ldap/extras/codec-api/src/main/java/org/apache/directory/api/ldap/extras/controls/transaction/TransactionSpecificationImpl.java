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
package org.apache.directory.api.ldap.extras.controls.transaction;

import java.util.Arrays;

import org.apache.directory.api.ldap.model.message.controls.AbstractControl;
import org.apache.directory.api.util.Strings;

/**
 * The Transaction Specification control. It's defined in RFC 5805.
 * This control is sent with every update once a transaction is started.
 * It contains the Transaction ID. 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TransactionSpecificationImpl extends AbstractControl implements TransactionSpecification
{
    /** The Transaction Specification identifier */
    private byte[] identifier;

    /**
     * Default constructor
     */
    public TransactionSpecificationImpl()
    {
        super( OID );
    }
    

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getIdentifier()
    {
        return identifier;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setIdentifier( byte[] identifier )
    {
        // Copy the byte[]
        if ( identifier != null )
        {
            this.identifier = new byte[identifier.length];
            System.arraycopy( identifier, 0, this.identifier, 0, identifier.length );
        }
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = super.hashCode();

        if ( identifier != null )
        {
            for ( byte b : identifier )
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
        
        if ( !( o instanceof TransactionSpecification ) )
        {
            return false;
        }

        TransactionSpecification otherControl = ( TransactionSpecification ) o;

        return super.equals( o )
            && Arrays.equals( identifier, otherControl.getIdentifier() );
    }
    
    
    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    Transaction Spcecification control :\n" );
        sb.append( "        oid : " ).append( getOid() ).append( '\n' );
        sb.append( "        critical : " ).append( isCritical() ).append( '\n' );
        
        if ( identifier != null )
        {
            sb.append( "        Transaction ID=null" ).append( '\n' );
        }
        else
        {
            sb.append( "        Transaction ID=" ).append( Strings.dumpBytes( identifier ) ).append( '\n' );
        }
        
        return sb.toString();
    }
}
