package com.michelin.cio.hudson.plugins.rolestrategy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RoleSid implements Comparable {

    protected String name;

    private Pattern pattern;

    private transient Integer cachedHashCode = null;

    RoleSid(String name) {
        this.name = name;
        this.pattern = Pattern.compile(name);
    }

    RoleSid(String name, boolean useMatching){
        this.name = name;
        if( useMatching){
            this.pattern = Pattern.compile(name);
        }
    }

    public String getName() {
        return name;
    }

    public Matcher matches(String name ){
        return pattern.matcher(name);
    }

    @Override
    public int hashCode() {
        if (cachedHashCode == null) {
            cachedHashCode = _hashCode();
        }
        return cachedHashCode;
    }

    private int _hashCode() {
        return this.name.hashCode();
    }

    public int compareTo(Object o){
        if( o instanceof String){
            return this.name.compareTo(((String) o));
        } else if( o instanceof RoleSid){
            return this.name.compareTo(((RoleSid)o).getName());
        }

        return -1;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }

        return this.toString().equals(obj.toString());

    }

    @Override
    public String toString(){
        return getName();
    }
}
