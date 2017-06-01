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


import java.util.List;
import java.util.Map;


/**
 * Utility class used to generate schema object specifications. Some of the
 * latest work coming out of the LDAPBIS working body adds optional extensions
 * to these syntaxes. Descriptions can be generated for
 * the following objects:
 * <ul>
 * <li><a href="./AttributeType.html">AttributeType</a></li>
 * <li><a href="./DitContentRule.html">DitContentRule</a></li>
 * <li><a href="./DitContentRule.html">DitStructureRule</a></li>
 * <li><a href="./LdapComparator.html">Syntax</a></li>
 * <li><a href="./MatchingRule.html">MatchingRule</a></li>
 * <li><a href="./MatchingRuleUse.html">MatchingRuleUse</a></li>
 * <li><a href="./NameForm.html">NameForm</a></li>
 * <li><a href="./Normalizer.html">Syntax</a></li>
 * <li><a href="./ObjectClass.html">ObjectClass</a></li>
 * <li><a href="./LdapSyntax.html">Syntax</a></li>
 * <li><a href="./SyntaxChecker.html">Syntax</a></li>
 * </ul>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class DescriptionUtils
{
    /**
     * Private constructor.
     */
    private DescriptionUtils()
    {
    }


    /**
     * Generates the ComparatorDescription for a LdapComparator. Only the right 
     * hand side of the description starting at the opening parenthesis is 
     * generated: that is 'ComparatorDescription = ' is not generated.
     * 
     * <pre>
     * ComparatorDescription = &quot;(&quot;
     *     numericoid                          
     *     [&quot;DESC&quot; qdstring ]
     *     &quot;FQCN&quot; whsp fqcn
     *     [&quot;BYTECODE&quot; whsp base64  ]
     *     extensions 
     *     &quot;)&quot;
     * </pre>
     * 
     * @param comparator
     *            the Comparator to generate the description for
     * @return the ComparatorDescription string
     */
    public static String getDescription( LdapComparator<?> comparator )
    {
        return getLoadableDescription( comparator );
    }


    /**
     * Generates the NormalizerDescription for a Normalizer. Only the right 
     * hand side of the description starting at the opening parenthesis is 
     * generated: that is 'NormalizerDescription = ' is not generated.
     * 
     * <pre>
     * NormalizerDescription = &quot;(&quot;
     *     numericoid                          
     *     [&quot;DESC&quot; qdstring ]
     *     &quot;FQCN&quot; whsp fqcn
     *     [&quot;BYTECODE&quot; whsp base64  ]
     *     extensions 
     *     &quot;)&quot;
     * </pre>
     * 
     * @param normalizer
     *            the Normalizer to generate the description for
     * @return the NormalizerDescription string
     */
    public static String getDescription( Normalizer normalizer )
    {
        return getLoadableDescription( normalizer );
    }


    /**
     * Generates the SyntaxCheckerDescription for a SyntaxChecker. Only the right 
     * hand side of the description starting at the opening parenthesis is 
     * generated: that is 'SyntaxCheckerDescription = ' is not generated.
     * 
     * <pre>
     * SyntaxCheckerDescription = &quot;(&quot;
     *     numericoid                          
     *     [&quot;DESC&quot; qdstring ]
     *     &quot;FQCN&quot; whsp fqcn
     *     [&quot;BYTECODE&quot; whsp base64  ]
     *     extensions 
     *     &quot;)&quot;
     * </pre>
     * 
     * @param syntaxChecker
     *            the SyntaxChecker to generate the description for
     * @return the SyntaxCheckerDescription string
     */
    public static String getDescription( SyntaxChecker syntaxChecker )
    {
        return getLoadableDescription( syntaxChecker );
    }


    private static void getExtensions( StringBuilder sb, Map<String, List<String>> extensions )
    {
        for ( Map.Entry<String, List<String>> extension : extensions.entrySet() )
        {
            sb.append( ' ' ).append( extension.getKey() ).append( ' ' );

            List<String> values = extension.getValue();

            if ( ( values != null ) && !values.isEmpty() )
            {
                if ( values.size() == 1 )
                {
                    sb.append( values.get( 0 ) );
                }
                else
                {
                    boolean isFirst = true;
                    sb.append( "( " );

                    for ( String value : values )
                    {
                        if ( isFirst )
                        {
                            isFirst = false;
                        }
                        else
                        {
                            sb.append( ' ' );
                        }

                        sb.append( value );
                    }

                    sb.append( " )" );
                }
            }

            sb.append( '\n' );
        }
    }


    /**
     * Generate the description for Comparators, Normalizers and SyntaxCheckers.
     */
    private static String getLoadableDescription( LoadableSchemaObject schemaObject )
    {
        StringBuilder buf = new StringBuilder( "( " );
        buf.append( schemaObject.getOid() );
        buf.append( '\n' );

        if ( schemaObject.getDescription() != null )
        {
            buf.append( " DESC " );
            buf.append( schemaObject.getDescription() );
            buf.append( '\n' );
        }

        if ( schemaObject.getFqcn() != null )
        {
            buf.append( " FQCN " );
            buf.append( schemaObject.getFqcn() );
            buf.append( '\n' );
        }

        if ( schemaObject.getBytecode() != null )
        {
            buf.append( " BYTECODE " );

            // We will dump only the 16 first bytes
            if ( schemaObject.getBytecode().length() > 16 )
            {
                buf.append( schemaObject.getBytecode().substring( 0, 16 ) );
            }
            else
            {
                buf.append( schemaObject.getBytecode() );
            }

            buf.append( '\n' );
        }

        if ( schemaObject.getExtensions() != null )
        {
            getExtensions( buf, schemaObject.getExtensions() );
        }

        buf.append( " ) " );

        return buf.toString();
    }
}
