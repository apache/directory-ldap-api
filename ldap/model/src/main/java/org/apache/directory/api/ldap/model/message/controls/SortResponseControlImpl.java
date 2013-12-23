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

/**
 * Implementation of SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortResponseControlImpl extends AbstractControl  implements SortResponseControl
{
    /** the sort operations result code */
    private SortResultCode result;
    
    /** name of the first offending attribute */
    private String attributeName;
    
    public SortResponseControlImpl()
    {
        super( OID );
    }

    @Override
    public void setSortResult( SortResultCode result )
    {
        this.result = result;
    }

    @Override
    public SortResultCode getSortResult()
    {
        return result;
    }

    @Override
    public void setAttibuteName( String attributeName )
    {
        this.attributeName = attributeName;
    }

    @Override
    public String getAttibuteName()
    {
        return attributeName;
    }

    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ( ( attributeName == null ) ? 0 : attributeName.hashCode() );
        result = prime * result + ( ( this.result == null ) ? 0 : this.result.hashCode() );
        return result;
    }

    @Override
    public boolean equals( Object o )
    {
        if( !super.equals( o ) )
        {
            return false;
        }
        
        SortResponseControl that = ( SortResponseControl ) o;
        
        if( result != that.getSortResult() )
        {
            return false;
        }
        
        if( attributeName != null )
        {
            return ( attributeName.equalsIgnoreCase( that.getAttibuteName() ) );
        }
        else if( that.getAttibuteName() == null )
        {
            return true;
        }
        
        return false;
    }

    @Override
    public String toString()
    {
        return "SortResponseControlImpl [result=" + result + ", attributeName=" + attributeName + "]";
    }
    
}
