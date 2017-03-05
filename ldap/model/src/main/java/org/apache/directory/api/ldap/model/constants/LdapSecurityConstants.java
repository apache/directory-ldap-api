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
package org.apache.directory.api.ldap.model.constants;


/**
 * An enum to store all the security constants used in the server
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public enum LdapSecurityConstants
{
    /** The SHA encryption method */
    HASH_METHOD_SHA("SHA", "SHA", "sha"),

    /** The Salted SHA encryption method */
    HASH_METHOD_SSHA("SSHA", "SHA", "ssha"),

    /** The SHA-256 encryption method */
    HASH_METHOD_SHA256("SHA-256", "SHA-256", "sha256"),

    /** The salted SHA-256 encryption method */
    HASH_METHOD_SSHA256("SSHA-256", "SHA-256", "ssha256"),

    /** The SHA-384 encryption method */
    HASH_METHOD_SHA384("SHA-384", "SHA-384", "sha384"),

    /** The salted SHA-384 encryption method */
    HASH_METHOD_SSHA384("SSHA-384", "SHA-384", "ssha384"),

    /** The SHA-512 encryption method */
    HASH_METHOD_SHA512("SHA-512", "SHA-512", "sha512"),

    /** The salted SHA-512 encryption method */
    HASH_METHOD_SSHA512("SSHA-512", "SHA-512", "ssha512"),

    /** The MD5 encryption method */
    HASH_METHOD_MD5("MD5", "MD5", "md5"),

    /** The Salter MD5 encryption method */
    HASH_METHOD_SMD5("SMD5", "MD5", "smd5"),

    /** The crypt encryption method */
    HASH_METHOD_CRYPT("CRYPT", "CRYPT", "crypt"),
    
    /** The crypt (MD5) encryption method */
    HASH_METHOD_CRYPT_MD5("CRYPT-MD5", "MD5", "crypt", "$1$"),
    
    /** The crypt (SHA-256) encryption method */
    HASH_METHOD_CRYPT_SHA256("CRYPT-SHA-256", "SHA-256", "crypt", "$5$"),
    
    /** The crypt (SHA-512) encryption method */
    HASH_METHOD_CRYPT_SHA512("CRYPT-SHA-512", "SHA-512", "crypt", "$6$"),
    
    /** The BCrypt encryption method */
    HASH_METHOD_CRYPT_BCRYPT("CRYPT-BCRYPT", "BCRYPT", "crypt", "$2a$"),

    /** The PBKDF2-based encryption method */
    HASH_METHOD_PKCS5S2("PKCS5S2", "PBKDF2WithHmacSHA1", "PKCS5S2");

    /* These encryption types are not yet supported 
    ** The AES encryption method *
    ENC_METHOD_AES("aes"),
    
    ** The 3DES encryption method *
    ENC_METHOD_3DES("3des"),
    
    ** The Blowfish encryption method *
    ENC_METHOD_BLOWFISH("blowfish"),
    
    ** The RC4 encryption method *
    ENC_METHOD_RC4("rc4");
    */

    /** The associated name */
    private String name;

    /** The associated algorithm */
    private String algorithm;

    /** The associated prefix */
    private String prefix;
    
    /** The optional sub-prefix */
    private String subPrefix;

    
    /**
     * Creates a new instance of LdapSecurityConstants.
     * 
     * @param name the associated name
     * @param algorithm the associated algorithm
     * @param prefix the associated prefix
     */
    LdapSecurityConstants( String name, String algorithm, String prefix )
    {
        this( name, algorithm, prefix, "" );
    }

    /**
     * Creates a new instance of LdapSecurityConstants.
     * 
     * @param name the associated name
     * @param algorithm the associated algorithm
     * @param prefix the associated prefix
     * @param subPrefix the optional sub-prefix
     */
    LdapSecurityConstants( String name, String algorithm, String prefix, String subPrefix )
    {
        this.name = name;
        this.algorithm = algorithm;
        this.prefix = prefix;
        this.subPrefix = subPrefix;
    }


    /**
     * @return the name associated with the constant.
     */
    public String getName()
    {
        return name;
    }


    /**
     * @return the prefix associated with the constant.
     */
    public String getAlgorithm()
    {
        return algorithm;
    }


    /**
     * @return the prefix associated with the constant.
     */
    public String getPrefix()
    {
        return prefix;
    }


    /**
     * @return the optional sub-prefix associated with the constant.
     */
    public String getSubPrefix()
    {
        return subPrefix;
    }


    /**
     * Get the associated constant from a string
     *
     * @param algorithm The algorithm's name
     * @return The associated constant
     */
    public static LdapSecurityConstants getAlgorithm( String algorithm )
    {
        if ( matches( algorithm, HASH_METHOD_SHA ) )
        {
            return HASH_METHOD_SHA;
        }

        if ( matches( algorithm, HASH_METHOD_SSHA ) )
        {
            return HASH_METHOD_SSHA;
        }
        if ( matches( algorithm, HASH_METHOD_MD5 ) )
        {
            return HASH_METHOD_MD5;
        }

        if ( matches( algorithm, HASH_METHOD_SMD5 ) )
        {
            return HASH_METHOD_SMD5;
        }

        if ( matches( algorithm, HASH_METHOD_CRYPT ) )
        {
            return HASH_METHOD_CRYPT;
        }

        if ( matches( algorithm, HASH_METHOD_CRYPT_MD5 ) )
        {
            return HASH_METHOD_CRYPT_MD5;
        }

        if ( matches( algorithm, HASH_METHOD_CRYPT_SHA256 ) )
        {
            return HASH_METHOD_CRYPT_SHA256;
        }

        if ( matches( algorithm, HASH_METHOD_CRYPT_SHA512 ) )
        {
            return HASH_METHOD_CRYPT_SHA512;
        }

        if ( matches( algorithm, HASH_METHOD_CRYPT_BCRYPT ) )
        {
            return HASH_METHOD_CRYPT_BCRYPT;
        }

        if ( matches( algorithm, HASH_METHOD_SHA256 ) )
        {
            return HASH_METHOD_SHA256;
        }

        if ( matches( algorithm, HASH_METHOD_SSHA256 ) )
        {
            return HASH_METHOD_SSHA256;
        }

        if ( matches( algorithm, HASH_METHOD_SHA384 ) )
        {
            return HASH_METHOD_SHA384;
        }

        if ( matches( algorithm, HASH_METHOD_SSHA384 ) )
        {
            return HASH_METHOD_SSHA384;
        }

        if ( matches( algorithm, HASH_METHOD_SHA512 ) )
        {
            return HASH_METHOD_SHA512;
        }

        if ( matches( algorithm, HASH_METHOD_SSHA512 ) )
        {
            return HASH_METHOD_SSHA512;
        }

        if ( matches( algorithm, HASH_METHOD_PKCS5S2 ) )
        {
            return HASH_METHOD_PKCS5S2;
        }

        /*
        if ( ENC_METHOD_AES.name.equalsIgnoreCase( algorithm ) )
        {
            return ENC_METHOD_AES;
        }

        if ( ENC_METHOD_3DES.name.equalsIgnoreCase( algorithm ) )
        {
            return ENC_METHOD_3DES;
        }

        if ( ENC_METHOD_BLOWFISH.name.equalsIgnoreCase( algorithm ) )
        {
            return ENC_METHOD_BLOWFISH;
        }

        if ( ENC_METHOD_RC4.name.equalsIgnoreCase( algorithm ) )
        {
            return ENC_METHOD_RC4;
        }
        */

        return null;
    }


    private static boolean matches( String algorithm, LdapSecurityConstants constant )
    {
        return constant.name.equalsIgnoreCase( algorithm )
            || ( constant.prefix + constant.subPrefix ).equalsIgnoreCase( algorithm );
    }

}
