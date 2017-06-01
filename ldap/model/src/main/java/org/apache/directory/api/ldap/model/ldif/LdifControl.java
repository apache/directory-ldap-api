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
package org.apache.directory.api.ldap.model.ldif;


import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;


/**
 * The LdifControl class stores a control defined for an entry found in a LDIF
 * file.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdifControl implements Control, Externalizable
{
    /** The control type */
    private String oid;

    /** The criticality (default value is false) */
    private boolean criticality = false;

    /** Optional control value */
    protected byte[] value;


    /**
     * Create a new Control
     */
    public LdifControl()
    {
    }


    /**
     * Create a new Control
     * 
     * @param oid OID of the created control
     */
    public LdifControl( String oid )
    {
        this.oid = oid;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "LdifControl : {" + getOid() + ", " + isCritical() + ", " + Strings.dumpBytes( getValue() ) + "}";
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return oid;
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
    public void setCritical( boolean criticality )
    {
        this.criticality = criticality;
    }


    /**
     * Get back the control value
     * 
     * @return The control's value
     */
    public byte[] getValue()
    {
        return value;
    }


    /**
     * Store the control value
     * 
     * @param value The value to store
     */
    public void setValue( byte[] value )
    {
        this.value = value;
    }


    /**
     * @return <t>TRUE</t> if the control has a value
     */
    public boolean hasValue()
    {
        return value != null;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        out.writeUTF( oid );
        out.writeBoolean( criticality );

        if ( hasValue() )
        {
            out.writeBoolean( true );
            out.writeInt( value.length );

            if ( value.length > 0 )
            {
                out.write( value );
            }
        }
        else
        {
            out.writeBoolean( false );
        }

        out.flush();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        oid = in.readUTF();
        criticality = in.readBoolean();

        if ( in.readBoolean() )
        {
            int valueLength = in.readInt();

            if ( valueLength > 0 )
            {
                value = new byte[valueLength];
                in.readFully( value );
            }
        }
    }


    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        int h = 17;
        h = h * 37 + ( criticality ? 1 : 0 );
        h = h * 37 + ( oid == null ? 0 : oid.hashCode() );

        if ( value != null )
        {
            for ( byte v : value )
            {
                h = h * 37 + v;
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
        if ( o == this )
        {
            return true;
        }

        if ( o == null )
        {
            return false;
        }

        if ( !( o instanceof Control ) )
        {
            return false;
        }

        Control otherControl = ( Control ) o;

        if ( !oid.equalsIgnoreCase( otherControl.getOid() ) )
        {
            return false;
        }

        return criticality == otherControl.isCritical();
    }
}
