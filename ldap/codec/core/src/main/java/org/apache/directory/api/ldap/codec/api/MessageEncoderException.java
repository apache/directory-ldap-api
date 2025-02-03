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
package org.apache.directory.api.ldap.codec.api;


import org.apache.directory.api.asn1.EncoderException;


/**
 * Create an exception containing the messageId
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class MessageEncoderException extends EncoderException
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = -4634398228257729537L;

    /** The message ID */
    private final int messageId;


    /**
     * Creates a new instance of MessageEncoderException.
     *
     * @param messageId The message ID
     * @param message The exception message
     */
    public MessageEncoderException( int messageId, String message )
    {
        super( message );
        this.messageId = messageId;
    }


    /**
     * Creates a new instance of MessageEncoderException.
     *
     * @param messageId The message ID
     * @param message The exception message
     * @param cause The parent exception
     */
    public MessageEncoderException( int messageId, String message, Exception cause )
    {
        super( message, cause );
        this.messageId = messageId;
    }


    /**
     * Get the message ID
     * 
     * @return the messageId
     */
    public int getMessageId()
    {
        return messageId;
    }
}
