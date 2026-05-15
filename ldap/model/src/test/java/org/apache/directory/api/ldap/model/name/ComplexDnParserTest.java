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
package org.apache.directory.api.ldap.model.name;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;

import org.apache.directory.api.util.Position;
import org.apache.directory.api.util.Strings;
import org.junit.jupiter.api.Test;

/**
 * Test the class AttributeTypeAndValue
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class ComplexDnParserTest {
    
    private static Method getPrivateMethod( String methodName, Class<?> clazz ) throws IllegalAccessException, IllegalArgumentException, 
        InvocationTargetException, NoSuchMethodException, SecurityException 
    {
        Method method = ComplexDnParser.class.getDeclaredMethod( methodName, clazz, Position.class );
        method.setAccessible( true );

        return method;
    }

    /**
     * test for a simple AT like "objectClass"
     */
    @Test
    void testParseSimpelAttributeType()
    {
        try {
            Method method = getPrivateMethod( "parseAttributeType", byte[].class );
            
            // Check a simple attributeType
            // Transition Start -> 1
            String at = "objectClass";
            Position pos = new Position( at );
            pos.length = at.length(); 
            
            String attributeType = ( String ) method.invoke( null, Strings.getBytesUtf8( at ), pos );
            
            assertEquals( at, attributeType );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    /**
     * test for a not terminated numericOID AT like "oid.1.2.3"
     */
    @Test
    void testParseOidNumericOidAttributeType()
    {
        try {
            Method method = getPrivateMethod( "parseAttributeType", byte[].class );
            
            // Check a simple attributeType
            // Transition Start -> 1
            String at = "oid.1.2.3";
            Position pos = new Position( at );
            pos.length = at.length(); 
            
            String attributeType = ( String ) method.invoke( null, Strings.getBytesUtf8( at ), pos );
            
            assertEquals( at, attributeType );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    /**
     * test for a bad  numericOID AT like "123"
     */
    @Test
    void testParseBadNumericOidAttributeType()
    {
        try {
            Method method = getPrivateMethod( "parseAttributeType", byte[].class );
            
            // Check a wrong OID
            String at = "123";
            Position pos = new Position( at );
            pos.length = at.length(); 
            
            try 
            {
                method.invoke( null, Strings.getBytesUtf8( at ), pos );
            }
            catch ( Exception e )
            {
                assertTrue( e.getCause().getMessage().startsWith("ERR_13630_BAD_OID_ATTRIBUTE_TYPE" ) );
            }
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }


    /**
     * test for a not terminated numericOID AT like "123.2."
     */
    @Test
    void testParseNotTerminatedNumericOidAttributeType()
    {
        try {
            Method method = getPrivateMethod( "parseAttributeType", byte[].class );
            
            // Check a wrong OID
            String at = "123.2.";
            Position pos = new Position( at );
            pos.length = at.length(); 
            pos.end = pos.length;
            
            try 
            {
                method.invoke( null, Strings.getBytesUtf8( at ), pos );
            }
            catch ( Exception e )
            {
                assertTrue( e.getCause().getMessage().startsWith("ERR_13630_BAD_OID_ATTRIBUTE_TYPE" ) );
            }
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    @Test
    void testParseUTFMB2_00A3() throws ParseException
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xC2, ( byte ) 0xA3 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\u00A3' /*'£'*/, c );
            assertEquals( '£', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
   }
    
    
    /**
     * %xE0 %xA0-BF UTF0
     */
    @Test
    void testParseUTFMB3_1_0920()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xE0, ( byte ) 0xA4, ( byte ) 0xA0 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\u0920' /*'ठ'*/, c );
            assertEquals( 'ठ', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xE1-EC 2(UTF0)
     */
    @Test
    void testParseUTFMB3_2_1200()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xE1, ( byte ) 0x88, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\u1200' /*'ሀ'*/ , c);
            assertEquals( 'ሀ', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xE1-EC 2(UTF0)
     */
    @Test
    void testParseWrongUTFMB3_2()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xE1, ( byte ) 0x45, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            assertThrows( InvocationTargetException.class, () -> method.invoke( null, bytes, pos ) );
            
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException |
                InvocationTargetException e ) {
            e.printStackTrace();
        }
    }
      
    
    /**
     * %xED %x80-9F UTF0
     */
    @Test
    void testParseUTFMB3_3_D000()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xED, ( byte ) 0x80, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\uD000' /*'퀀'*/, c );
            assertEquals( '퀀' /*'퀀'*/, c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * %xED %x80-9F UTF0
     */
    @Test
    void testParseUTFMB3_3_D7FB()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xED, ( byte ) 0x9F, ( byte ) 0xBB };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\uD7FB' /*'ퟻ'*/, c );
            assertEquals( 'ퟻ', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xEE-EF 2(UTF0)
     */
    @Test
    void testParseUTFMB3_4_E000()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xEE, ( byte ) 0x80, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\uE000' /*''*/, c );
            assertEquals( '', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xEE-EF 2(UTF0)
     */
    @Test
    void testParseUTFMB3_4_FFFD()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xEF, ( byte ) 0xBF, ( byte ) 0xBD };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            
            assertEquals( '\uFFFD' /*'�'*/, c );
            assertEquals( '�', c );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xF0 %x90-BF 2(UTF0)
     */
    @Test
    void testParseUTFMB4_1_10000()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xF0, ( byte ) 0x90, ( byte ) 0x80, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            char[] chars = new char[] { ( char )( c >> 16 ), ( char ) ( c & 0xFFFF ) };
            String result = new String( chars );
            assertEquals( "\uD800\uDC00" /*'𐀀'*/, result );
            assertEquals( "𐀀", result );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xF0 %x90-BF 2(UTF0)
     */
    @Test
    void testParseUTFMB4_1_3D05F()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xF0, ( byte ) 0xBD, ( byte ) 0x81, ( byte ) 0x9F };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            char[] chars = new char[] { ( char )( c >> 16 ), ( char ) ( c & 0xFFFF ) };
            String result = new String( chars );
            assertEquals( "\uD8B4\uDC5F" /*'𽁟'*/, result );
            assertEquals( "𽁟", result );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xF1-F3 3(UTF0)
     */
    @Test
    void testParseUTFMB4_2_E0052()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xF3, ( byte ) 0xA0, ( byte ) 0x81, ( byte ) 0x92 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            char[] chars = new char[] { ( char )( c >> 16 ), ( char ) ( c & 0xFFFF ) };
            String result = new String( chars );
            assertEquals( "\uDB40\uDC52", result );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xF4 %x80-8F 2(UTF0)
     */
    @Test
    void testParseUTFMB4_3_100000()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xF4, ( byte ) 0x80, ( byte ) 0x80, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            char[] chars = new char[] { ( char )( c >> 16 ), ( char ) ( c & 0xFFFF ) };
            String result = new String( chars );
            assertEquals( "\uDBC0\uDC00", result );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
    
    
    /**
     * %xF4 %x80-8F 2(UTF0)
     */
    @Test
    void testParseUTFMB4_3_10FFFF()
    {
        try {
            Method method = getPrivateMethod( "parseUTFMB", byte[].class );

            byte[] bytes = new byte[] { ( byte ) 0xF4, ( byte ) 0x80, ( byte ) 0x80, ( byte ) 0x80 };
            Position pos  = new Position( bytes );
            pos.length = bytes.length;
            
            int c = ( int ) method.invoke( null, bytes, pos );
            char[] chars = new char[] { ( char )( c >> 16 ), ( char ) ( c & 0xFFFF ) };
            String result = new String( chars );
            assertEquals( "\uDBC0\uDC00", result );
        } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            e.printStackTrace();
        }
    }
}
