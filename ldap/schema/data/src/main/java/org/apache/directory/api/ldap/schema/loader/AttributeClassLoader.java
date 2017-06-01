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
package org.apache.directory.api.ldap.schema.loader;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;


/**
 * A class loader that loads classes from an attribute within an entry.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributeClassLoader extends ClassLoader
{
    /** The attribute. */
    private Attribute attribute;


    /**
     * Instantiates a new attribute class loader.
     */
    public AttributeClassLoader()
    {
        super( AttributeClassLoader.class.getClassLoader() );
    }


    /**
     * Sets the attribute.
     *
     * @param attribute the new attribute
     * @throws LdapException if the attribute is not binary.
     */
    public void setAttribute( Attribute attribute ) throws LdapException
    {
        if ( attribute.isHumanReadable() )
        {
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.CONSTRAINT_VIOLATION,
                I18n.err( I18n.ERR_10001 ) );
        }

        this.attribute = attribute;
    }

    
    /**
     * Read data from a jar, and write them into a byte[]
     */
    private static byte[] getBytes( InputStream input ) throws IOException 
    {
        ByteArrayOutputStream result = new ByteArrayOutputStream();

        byte[] buf = new byte[2048];
        int bytesRead = input.read( buf );

        while ( bytesRead != -1 ) 
        {
            result.write( buf, 0, bytesRead );
            bytesRead = input.read( buf );
        }
      
        result.flush();
        result.close();
        
        return result.toByteArray();
    }

    
    private Map<String, Class<?>> loadClasses( byte[] jarBytes ) throws IOException 
    {
        Map<String, Class<?>> map = new HashMap<>();
        
        try ( JarInputStream jis = new JarInputStream( new ByteArrayInputStream( jarBytes ) ) ) 
        {
            JarEntry entry;
            boolean isJar = false;
            
            while ( ( entry = jis.getNextJarEntry() ) != null ) 
            {
                String fileName = entry.getName();
                isJar = true;
                
                // Just consider the files ending with .class
                if ( fileName.endsWith( ".class" ) )
                {
                    String className = fileName.substring( 0,  fileName.length() - ".class".length() ).replace( '/', '.' );
                    byte[] classBytes = getBytes( jis );
                    
                    Class<?> clazz = defineClass( className, classBytes, 0, classBytes.length );
                    map.put( className, clazz );
                }
            }
            
            if ( !isJar )
            {
                return null;
            }
        }

        return map;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<?> findClass( String name ) throws ClassNotFoundException
    {
        byte[] classBytes;

        Value<?> value = attribute.get();

        if ( value.isHumanReadable() )
        {
            throw new ClassNotFoundException( I18n.err( I18n.ERR_10002 ) );
        }

        classBytes = value.getBytes();

        // May be we are dealing with a JAR ?
        try 
        {
            Map<String, Class<?>> classes = loadClasses( classBytes );
            
            if ( classes == null )
            {
                // May be a simple class ?
                return defineClass( name, classBytes, 0, classBytes.length );
            }
            
            for ( Map.Entry<String, Class<?>> entry : classes.entrySet() )
            {
                if ( entry.getKey().contains( name ) )
                {
                    return entry.getValue();
                }
            }
        }
        catch ( IOException ioe )
        {
            // Ok, may be a pure class
            return defineClass( name, classBytes, 0, classBytes.length );
        }
        
        return null;
    }
}
