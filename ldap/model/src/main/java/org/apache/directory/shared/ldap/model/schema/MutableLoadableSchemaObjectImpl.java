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
package org.apache.directory.shared.ldap.model.schema;


import org.apache.directory.shared.i18n.I18n;
import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.schema.registries.Registries;
import org.apache.directory.shared.util.Strings;


/**
 * An abstract class used to manage the ADS specific SchemaObject, which can
 * contain some compiled Java class to implement the specific logic.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class MutableLoadableSchemaObjectImpl extends AbstractMutableSchemaObject implements LoadableSchemaObject, MutableLoadableSchemaObject
{
    private static final long serialVersionUID = 8370373510870284033L;

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
    protected MutableLoadableSchemaObjectImpl( SchemaObjectType objectType, String oid )
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
    protected MutableLoadableSchemaObjectImpl( SchemaObjectType objectType )
    {
        super( objectType );

        fqcn = "";
        bytecode = null;
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.ldap.model.schema.LoadableSchemaObject#getBytecode()
     */
    public String getBytecode()
    {
        return bytecode;
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.ldap.model.schema.MutableLoadableSchemaObject#setBytecode(java.lang.String)
     */
    public void setBytecode( String bytecode )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.bytecode = bytecode;
        }
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.ldap.model.schema.LoadableSchemaObject#getFqcn()
     */
    public String getFqcn()
    {
        return fqcn;
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.ldap.model.schema.MutableLoadableSchemaObject#setFqcn(java.lang.String)
     */
    public void setFqcn( String fqcn )
    {
        if ( locked )
        {
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_04441, getName() ) );
        }

        if ( !isReadOnly )
        {
            this.fqcn = fqcn;
        }
    }


    /**
     * {@inheritDoc}
     */
    public void registerOid( MutableSchemaObject schemaObject, Registries registries ) throws LdapException
    {
        // Do nothing : the current SchemaObject ha sthe same OID than the one it is realted to
    }


    /**
     * {@inheritDoc}
     */
    public LoadableSchemaObject copy()
    {
        return null;
    }

    
    /**
     * {@inheritDoc}
     */
    public MutableLoadableSchemaObject copyMutable()
    {
        return null;
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

        if ( !( o instanceof MutableLoadableSchemaObjectImpl ) )
        {
            return false;
        }

        MutableLoadableSchemaObjectImpl that = ( MutableLoadableSchemaObjectImpl ) o;

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


    /* (non-Javadoc)
     * @see org.apache.directory.shared.ldap.model.schema.LoadableSchemaObject#isValid()
     */
    public boolean isValid()
    {
        String className = this.getClass().getName();

        if ( Strings.isEmpty(fqcn) )
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
