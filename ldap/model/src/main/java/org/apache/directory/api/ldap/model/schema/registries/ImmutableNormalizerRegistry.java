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
package org.apache.directory.api.ldap.model.schema.registries;


import java.util.Iterator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SchemaObjectType;


/**
 * An immutable wrapper of the Normalizer registry.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableNormalizerRegistry implements NormalizerRegistry
{
    /** The wrapped Normalizer registry */
    NormalizerRegistry immutableNormalizerRegistry;


    /**
     * Creates a new immutable NormalizerRegistry instance.
     * 
     * @param normalizerRegistry The wrapped Normalizer registry 
     */
    public ImmutableNormalizerRegistry( NormalizerRegistry normalizerRegistry )
    {
        immutableNormalizerRegistry = normalizerRegistry;
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public void register( Normalizer normalizer ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public Normalizer unregister( String numericOid ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public void unregisterSchemaElements( String schemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public ImmutableNormalizerRegistry copy()
    {
        return ( ImmutableNormalizerRegistry ) immutableNormalizerRegistry.copy();
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public int size()
    {
        return immutableNormalizerRegistry.size();
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public boolean contains( String oid )
    {
        return immutableNormalizerRegistry.contains( oid );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public String getOidByName( String name ) throws LdapException
    {
        return immutableNormalizerRegistry.getOidByName( name );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public String getSchemaName( String oid ) throws LdapException
    {
        return immutableNormalizerRegistry.getSchemaName( oid );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public SchemaObjectType getType()
    {
        return immutableNormalizerRegistry.getType();
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public Iterator<Normalizer> iterator()
    {
        return immutableNormalizerRegistry.iterator();
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public Normalizer lookup( String oid ) throws LdapException
    {
        return immutableNormalizerRegistry.lookup( oid );
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public Iterator<String> oidsIterator()
    {
        return immutableNormalizerRegistry.oidsIterator();
    }


    /**
     *  {@inheritDoc}
     */
    @Override
    public void renameSchema( String originalSchemaName, String newSchemaName ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer get( String oid )
    {
        return immutableNormalizerRegistry.get( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clear() throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Normalizer unregister( Normalizer schemaObject ) throws LdapException
    {
        throw new LdapUnwillingToPerformException( ResultCodeEnum.NO_SUCH_OPERATION, I18n.err( I18n.ERR_04283 ) );
    }
}
