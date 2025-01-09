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
package org.apache.directory.api.ldap.model.schema;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.Strings;


/**
 * An abstract class used to manage the ADS specific SchemaObject, which can
 * contain some compiled Java class to implement the specific logic.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class LoadableSchemaObject extends AbstractSchemaObject
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** The Full Qualified Class Name */
    private String fqcn;

    /** The base64 encoded bytecode for this schema */
    private String bytecode;

    /**
     * Constructor to use when the OID is known in advance.
     * 
     * @param objectType The SchemaObject type
     * @param oid The SchemaObject OID
     */
    protected LoadableSchemaObject( SchemaObjectType objectType, String oid )
    {
        super( objectType, oid );

        fqcn = "";
        bytecode = null;
    }


    /**
     * Constructor to use when the OID is not known until after instantiation.
     * 
     * @param objectType The SchemaObject type
     */
    protected LoadableSchemaObject( SchemaObjectType objectType )
    {
        super( objectType );

        fqcn = "";
        bytecode = null;
    }


    /**
     * Get the SchemaObject bytecode
     * 
     * @return The associated bytecode of this SchemaObject instance
     */
    public String getBytecode()
    {
        return bytecode;
    }


    /**
     * Stores some bytecode representing the compiled Java class for this
     * SchemaObject instance.
     * 
     * @param bytecode The bytecode to store
     */
    public void setBytecode( String bytecode )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.bytecode = bytecode;
    }


    /**
     * Get the schemaObject fully qualified class name
     * 
     * @return The schemaObject instance Fully Qualified Class Name
     */
    public String getFqcn()
    {
        return fqcn;
    }


    /**
     * Set the Fully Qualified Class Name for this SchemaObject instance
     * class stored in the bytecode attribute
     * @param fqcn The Fully Qualified Class Name
     */
    public void setFqcn( String fqcn )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_13700_CANNOT_MODIFY_LOCKED_SCHEMA_OBJECT, getName() ) );
        }

        this.fqcn = fqcn;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LoadableSchemaObject copy()
    {
        return null;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = h;
        
        if ( fqcn != null )
        {
            hash = hash * 17 + fqcn.hashCode();
        }
        
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

        if ( !( o instanceof LoadableSchemaObject ) )
        {
            return false;
        }

        LoadableSchemaObject that = ( LoadableSchemaObject ) o;

        // Check the byteCode
        // TODO

        // Check the FQCN
        if ( fqcn == null )
        {
            return that.fqcn == null;
        }
        else
        {
            return fqcn.equals( that.fqcn );
        }
    }


    /**
     * Test that the FQCN is equal to the instance's name. If the FQCN is
     * empty, fill it with the instance's name
     *
     * @return true if the FQCN is correctly set
     */
    public boolean isValid()
    {
        String className = this.getClass().getName();

        if ( Strings.isEmpty( fqcn ) )
        {
            fqcn = className;
            return true;
        }
        else
        {
            return className.equals( fqcn );
        }
    }
}
