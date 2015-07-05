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
package org.apache.directory.api.util;


/**
 * Various UTF constants are kept here.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class UnicodeConstants
{
    public static final int UTF8_MULTI_BYTES_MASK = 0x0080;
    public static final int UTF8_TWO_BYTES_MASK = 0x00E0;
    public static final int UTF8_TWO_BYTES = 0x00C0;
    public static final int UTF8_THREE_BYTES_MASK = 0x00F0;
    public static final int UTF8_THREE_BYTES = 0x00E0;
    public static final int UTF8_FOUR_BYTES_MASK = 0x00F8;
    public static final int UTF8_FOUR_BYTES = 0x00F0;
    public static final int UTF8_FIVE_BYTES_MASK = 0x00FC;
    public static final int UTF8_FIVE_BYTES = 0x00F8;
    public static final int UTF8_SIX_BYTES_MASK = 0x00FE;
    public static final int UTF8_SIX_BYTES = 0x00FC;

    /** %01-%27 %2B-%5B %5D-%7F */
    public static final boolean[] UNICODE_SUBSET =
        {
            // '\0'
            false, true,  true,  true,  true,  true,  true,  true, 
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            // '(', ')', '*'
            false, false, false, true,  true,  true,  true,  true, 
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            // '\'
            true,  true,  true,  true,  false, true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
            true,  true,  true,  true,  true,  true,  true,  true,
        };
    public static final int CHAR_ONE_BYTE_MASK = 0xFFFFFF80;
    public static final int CHAR_TWO_BYTES_MASK = 0xFFFFF800;
    public static final int CHAR_THREE_BYTES_MASK = 0xFFFF0000;
    public static final int CHAR_FOUR_BYTES_MASK = 0xFFE00000;
    public static final int CHAR_FIVE_BYTES_MASK = 0xFC000000;
    public static final int CHAR_SIX_BYTES_MASK = 0x80000000;


    private UnicodeConstants()
    {
    }
}
