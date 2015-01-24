package org.apache.directory.ldap.client.api.search;


import java.util.ArrayList;
import java.util.List;


class SetOfFiltersFilter extends AbstractFilter
{
    private Operator operator;
    private List<Filter> filters;


    private SetOfFiltersFilter( Operator operator )
    {
        this.operator = operator;
        this.filters = new ArrayList<Filter>();
    }


    public SetOfFiltersFilter add( Filter filter )
    {
        filters.add( filter );
        return this;
    }


    public SetOfFiltersFilter addAll( Filter... filters )
    {
        for ( Filter filter : filters )
        {
            this.filters.add( filter );
        }
        return this;
    }


    public SetOfFiltersFilter addAll( List<Filter> filters )
    {
        this.filters.addAll( filters );
        return this;
    }


    public static SetOfFiltersFilter and( Filter... filters )
    {
        return new SetOfFiltersFilter( Operator.AND ).addAll( filters );
    }


    public static SetOfFiltersFilter or( Filter... filters )
    {
        return new SetOfFiltersFilter( Operator.OR ).addAll( filters );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        if ( filters.isEmpty() )
        {
            throw new IllegalStateException( "at least one filter required" );
        }

        builder.append( "(" ).append( operator.operator() );
        for ( Filter filter : filters )
        {
            filter.build( builder );
        }
        return builder.append( ")" );
    }

    public static enum Operator
    {
        AND("&"),
        OR("|");

        private String operator;


        private Operator( String operator )
        {
            this.operator = operator;
        }


        public String operator()
        {
            return operator;
        }
    }
}