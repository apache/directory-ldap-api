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
package org.apache.directory.api.ldap.model.schema;


import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import org.apache.directory.api.util.Strings;


/**
 * Various utility methods for sorting schema objects.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SchemaObjectSorter
{
    private SchemaObjectSorter()
    {
    }


    /**
     * Gets an hierarchical ordered {@link Iterable} of the given {@link AttributeType}s. 
     * In other words parent {@link AttributeType}s are returned before child {@link AttributeType}s.
     * @param attributeTypes list of attribute types to order
     * @return the hierarchical ordered attribute types
     */
    public static Iterable<AttributeType> hierarchicalOrdered( List<AttributeType> attributeTypes )
    {
        return new SchemaObjectIterable<>( attributeTypes, new ReferenceCallback<AttributeType>()
        {
            @Override
            public Collection<String> getSuperiorOids( AttributeType at )
            {
                return Collections.singleton( at.getSuperiorOid() );
            }
        } );
    }


    /**
     * Gets an hierarchical ordered {@link Iterable} of the given {@link ObjectClass}es. 
     * In other words parent {@link ObjectClass}es are returned before child {@link ObjectClass}es.
     * @param objectClasses list of object classes to order
     * @return the hierarchical ordered object classes
     */
    public static Iterable<ObjectClass> sortObjectClasses( List<ObjectClass> objectClasses )
    {
        return new SchemaObjectIterable<>( objectClasses, new ReferenceCallback<ObjectClass>()
        {
            @Override
            public Collection<String> getSuperiorOids( ObjectClass oc )
            {
                return oc.getSuperiorOids();
            }
        } );
    }

    private interface ReferenceCallback<T extends SchemaObject>
    {

        Collection<String> getSuperiorOids( T schemaObject );

    }

    private static final class SchemaObjectIterable<T extends SchemaObject> implements Iterable<T>
    {

        private final List<T> schemaObjects;
        private final ReferenceCallback<T> callback;


        private SchemaObjectIterable( List<T> schemaObjects, ReferenceCallback<T> callback )
        {
            this.schemaObjects = schemaObjects;
            this.callback = callback;
        }


        @Override
        public Iterator<T> iterator()
        {
            return new SchemaObjectIterator<>( schemaObjects, callback );
        }

    }

    private static final class SchemaObjectIterator<T extends SchemaObject> implements Iterator<T>
    {
        private final List<T> schemaObjects;
        private final ReferenceCallback<T> callback;

        private final Map<String, String> oid2numericOid;
        private final Map<String, T> numericOid2schemaObject;

        private int loopCount;
        private Iterator<Entry<String, T>> schemaObjectIterator;


        private SchemaObjectIterator( List<T> schemaObjects, ReferenceCallback<T> callback )
        {
            this.schemaObjects = schemaObjects;
            this.callback = callback;

            this.oid2numericOid = new HashMap<>();
            this.numericOid2schemaObject = new TreeMap<>();
            this.loopCount = 0;

            for ( T schemaObject : schemaObjects )
            {
                String oid = Strings.toLowerCaseAscii( schemaObject.getOid() );
                oid2numericOid.put( oid, oid );
                
                for ( String name : schemaObject.getNames() )
                {
                    oid2numericOid.put( Strings.toLowerCaseAscii( name ), oid );
                }
                
                numericOid2schemaObject.put( oid, schemaObject );
            }
        }


        @Override
        public boolean hasNext()
        {
            return !numericOid2schemaObject.isEmpty();
        }


        @Override
        public T next()
        {
            while ( !maxLoopCountReached() )
            {
                Iterator<Entry<String, T>> iterator = getIterator();

                while ( iterator.hasNext() )
                {
                    Entry<String, T> entry = iterator.next();
                    T schemaObject = entry.getValue();

                    Collection<String> superiorOids = callback.getSuperiorOids( schemaObject );

                    // schema object has no superior
                    if ( superiorOids == null )
                    {
                        iterator.remove();
                        return schemaObject;
                    }

                    boolean allSuperiorsProcessed = true;

                    for ( String superiorOid : superiorOids )
                    {
                        if ( superiorOid == null )
                        {
                            continue;
                        }

                        String superiorNumeridOid = oid2numericOid.get( Strings.toLowerCaseAscii( superiorOid ) );

                        // AT's superior is not within the processed AT list
                        if ( superiorNumeridOid == null )
                        {
                            continue;
                        }

                        T superiorSchemaObject = numericOid2schemaObject.get( Strings.toLowerCaseAscii( superiorNumeridOid ) );

                        // AT's superior was already removed
                        if ( superiorSchemaObject == null )
                        {
                            continue;
                        }

                        allSuperiorsProcessed = false;
                        break;
                    }

                    if ( allSuperiorsProcessed )
                    {
                        iterator.remove();
                        return schemaObject;
                    }
                }
            }
            throw new IllegalStateException( "Loop detected: " + numericOid2schemaObject.values() );
        }


        private Iterator<Entry<String, T>> getIterator()
        {
            if ( schemaObjectIterator != null && schemaObjectIterator.hasNext() )
            {
                return schemaObjectIterator;
            }

            if ( !maxLoopCountReached() )
            {
                schemaObjectIterator = numericOid2schemaObject.entrySet().iterator();
                loopCount++;
                return schemaObjectIterator;
            }

            throw new IllegalStateException( "Loop detected: " + numericOid2schemaObject.values() );
        }


        private boolean maxLoopCountReached()
        {
            return loopCount > schemaObjects.size();
        }


        @Override
        public void remove()
        {
            throw new UnsupportedOperationException();
        }

    }

}
