/*
 * Copyright (c) 2000 - 2006 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * 
 */

package org.apache.directory.shared.asn1.der;


import java.io.UnsupportedEncodingException;


/**
 * Interface for DER string objects.
 */
public abstract class DERString extends DERObject
{
    /**
     * Basic DERObject constructor.
     */
    DERString(int tag, byte[] value)
    {
        super( tag, value );
    }


    /**
     * Lazy accessor.
     * 
     * @return underlying byte array converted to a String
     */
    public String getString()
    {
        return byteArrayToString( value );
    }


    /**
     * Utility method for converting byte arrays to Strings.
     * 
     * @param bytes
     * @return String
     */
    protected static String byteArrayToString( byte[] bytes )
    {
        try
        {
            return new String( bytes, "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            return "";
        }
    }


    /**
     * Utility method for converting Strings to bytes.
     * 
     * @param string
     * @return bytes
     */
    protected static byte[] stringToByteArray( String string )
    {
        try
        {
            return string.getBytes( "UTF-8" );
        }
        catch ( UnsupportedEncodingException uee )
        {
            return new byte[]
                {};
        }
    }
}
