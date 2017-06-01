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
public class SortResponseControlImpl extends AbstractControl  implements SortResponse
{
    /** the sort operations result code */
    private SortResultCode result;
    
    /** name of the first offending attribute */
    private String attributeName;
    
    /**
     * Creates a new SortResponseControlImpl instance
     */
    public SortResponseControlImpl()
    {
        super( OID );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSortResult( SortResultCode result )
    {
        this.result = result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SortResultCode getSortResult()
    {
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setAttributeName( String attributeName )
    {
        this.attributeName = attributeName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAttributeName()
    {
        return attributeName;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int hash = super.hashCode();
        hash = prime * hash + ( ( attributeName == null ) ? 0 : attributeName.hashCode() );
        hash = prime * hash + ( ( this.result == null ) ? 0 : this.result.hashCode() );
        
        return hash;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }
        
        SortResponse that = ( SortResponse ) o;
        
        if ( result != that.getSortResult() )
        {
            return false;
        }
        
        if ( attributeName != null )
        {
            return attributeName.equalsIgnoreCase( that.getAttributeName() );
        }
        else if ( that.getAttributeName() == null )
        {
            return true;
        }
        
        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return "SortResponseControlImpl [result=" + result + ", attributeName=" + attributeName + "]";
    }
    
}
