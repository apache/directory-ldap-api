package org.apache.directory.ldap.client.api.search;


/**
 * A builder for constructing well formed search filters according to
 * <a href="https://tools.ietf.org/html/rfc1960.html">RFC 1960</a>.  This 
 * builder is most convenient when you use static imports.  For example:
 * <pre>
 * import static org.apache.directory.ldap.client.api.search.FilterBuilder.and;
 * import static org.apache.directory.ldap.client.api.search.FilterBuilder.equal;
 * import static org.apache.directory.ldap.client.api.search.FilterBuilder.or;
 * 
 * ...
 * 
 *         String filter = 
 *                 or(
 *                     and( 
 *                         equal( "givenName", "kermit" ), 
 *                         equal( "sn", "the frog" ) ),
 *                     and( 
 *                         equal( "givenName", "miss" ), 
 *                         equal( "sn", "piggy" ) ) )
 *                 .toString()
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterBuilder
{
    private Filter filter;


    private FilterBuilder( Filter filter )
    {
        this.filter = filter;
    }


    /**
     * Returns a new FilterBuilder that will <code>&</code> together all of the 
     * supplied filters.  For example:
     * 
     * <pre>
     * and( equal( "givenName", "kermit" ), equal( "sn", "the frog" ) ).toString()
     * </pre>
     * would result in the string:
     * <pre>
     * (&(givenName=kermit)(sn=the frog))
     * </pre>
     * 
     * Which would match all entries with a given name of <code>kermit</code>
     * and a surname <code>the frog</code>.
     *
     * @param filters The filters to and together
     * @return A new FilterBuilder
     */
    public static FilterBuilder and( FilterBuilder... filters )
    {
        SetOfFiltersFilter filter = SetOfFiltersFilter.and();
        for ( FilterBuilder builder : filters )
        {
            filter.add( builder.filter() );
        }
        return new FilterBuilder( filter );
    }


    /**
     * Returns a new FilterBuilder for testing the approximate equality of an 
     * attribute. For example:
     * 
     * <pre>
     * approximatelyEqual( "l", "san fransico" ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (l~=san fransico)
     * </pre>
     * 
     * Which <i>MIGHT</i> match results whose locality is 
     * <code>San Francisco</code>.  The matching rule used to apply this filter
     * is dependent on the server implementation.
     *
     * @param attribute The attribute 
     * @param value The value
     * @return A new FilterBuilder
     */
    public static FilterBuilder approximatelyEqual( String attribute, String value )
    {
        return new FilterBuilder( AttributeValueAssertionFilter.approximatelyEqual( attribute, value ) );
    }


    /**
     * Returns a new FilterBuilder for testing equality of an attribute. For 
     * example:
     * 
     * <pre>
     * equal( "cn", "Kermit The Frog" ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (cn>=Kermit The Frog)
     * </pre>
     * 
     * Which would match entries with the common name 
     * <code>Kermit The Frog</code>.
     *
     * @param attribute The attribute 
     * @param value The value
     * @return A new FilterBuilder
     */
    public static FilterBuilder equal( String attribute, String value )
    {
        return new FilterBuilder( AttributeValueAssertionFilter.equal( attribute, value ) );
    }


    private Filter filter()
    {
        return filter;
    }


    /**
     * Returns a new FilterBuilder for testing lexicographical greater than.  
     * For example:
     * 
     * <pre>
     * greaterThanOrEqual( "sn", "n" ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (sn>=n)
     * </pre>
     * 
     * which would match results whose surname starts with the second half of
     * the alphabet.  
     *
     * @param attribute The attribute 
     * @param value The value
     * @return A new FilterBuilder
     */
    public static FilterBuilder greaterThanOrEqual( String attribute, String value )
    {
        return new FilterBuilder( AttributeValueAssertionFilter.greaterThanOrEqual( attribute, value ) );
    }


    /**
     * Returns a new FilterBuilder for testing lexicographical less than.  For
     * example:
     * 
     * <pre>
     * lessThanOrEqual( "sn", "mzzzzzz" ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (sn<=mzzzzzz)
     * </pre>
     * 
     * which would match results whose surname starts with the first half of
     * the alphabet.  <i>Note, this is not perfect, but if you know anybody with
     * a last name that starts with an <code>m</code> followed by six
     * <code>z</code>'s...</i>
     *
     * @param attribute The attribute 
     * @param value The value
     * @return A new FilterBuilder
     */
    public static FilterBuilder lessThanOrEqual( String attribute, String value )
    {
        return new FilterBuilder( AttributeValueAssertionFilter.lessThanOrEqual( attribute, value ) );
    }


    /**
     * Returns a new FilterBuilder for negating another filter.  For example:
     * 
     * <pre>
     * not( present( "givenName" ) ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (!(givenName=*))
     * </pre>
     *
     * @param filter The filter to negate
     * @return A new FilterBuilder
     */
    public static FilterBuilder not( FilterBuilder filter )
    {
        return new FilterBuilder( UnaryFilter.not( filter.filter() ) );
    }


    /**
     * Returns a new FilterBuilder that will <code>|</code> together all of the 
     * supplied filters.  For example:
     * 
     * <pre>
     * or( equal( "givenName", "kermit" ), equal( "givenName", "walter" ) ).toString()
     * </pre>
     * would result in the string:
     * <pre>
     * (|(givenName=kermit)(givenName=walter))
     * </pre>
     * 
     * Which would match any entry with the <code>givenName</code> of either
     * <code>kermit</code> or <code>walter</code>.
     *
     * @param filters The filters to or together
     * @return A new FilterBuilder
     */
    public static FilterBuilder or( FilterBuilder... filters )
    {
        SetOfFiltersFilter filter = SetOfFiltersFilter.or();
        for ( FilterBuilder builder : filters )
        {
            filter.add( builder.filter() );
        }
        return new FilterBuilder( filter );
    }


    /**
     * Returns a new FilterBuilder for testing the presence of an attributes.  
     * For example:
     * 
     * <pre>
     * present( "givenName" ).toString();
     * </pre>
     * would result in the string:
     * <pre>
     * (givenName=*)
     * </pre>
     * 
     * Which would match any entry that has a <code>givenName</code> attribute.
     *
     * @param attribute The attribute to test the presence of
     * @return A new FilterBuilder
     */
    public static FilterBuilder present( String attribute )
    {
        return new FilterBuilder( AttributeFilter.present( attribute ) );
    }


    /**
     * Returns the string version of the filter represented by this FilterBuilder.
     * 
     * @return The string representation of the filter
     */
    @Override
    public String toString()
    {
        return filter.build().toString();
    }
}
