package com.michelin.cio.hudson.plugins.rolestrategy;

import hudson.security.Permission;
import org.apache.commons.collections.CollectionUtils;

import javax.annotation.CheckForNull;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MatchingRole extends Role {

    Matcher matcher = null;
    Role role = null;

    MatchingRole(Role role, Matcher matcher){
        this.role = role;
        this.matcher = matcher;
    }

    @Override
    public String getName() { return role.getName(); }

    /**
     * Getter for the regexp pattern.
     * @return The pattern associated to the role
     */
    @Override
    public Pattern getPattern() {
        return role.getPattern();
    }

    /**
     * Getter for the {@link Permission}s set.
     * @return {@link Permission}s set
     */
    @Override
    public Set< Permission > getPermissions() { return role.getPermissions(); }

    @Override
    @CheckForNull
    public String getDescription() {
        return role.getDescription();
    }

    /**
     * Checks if the role holds the given {@link Permission}.
     * @param permission The permission you want to check
     * @return True if the role holds this permission
     */
    @Override
    public Boolean hasPermission(Permission permission) {
        return role.hasPermission(permission);
    }

    @Override
    public Boolean hasAnyPermission(Set<Permission> permissions) {
        return role.hasAnyPermission(permissions);
    }

    @Override
    public Matcher getMatcher(){
        return matcher;
    }

    @Override
    public int hashCode() {
        return role.hashCode();
    }

    @Override
    public int compareTo(Object o) {
        if (o instanceof MatchingRole) {
            return getName().compareTo(((MatchingRole)o).getName());
        } else if( o instanceof Role){
            return getName().compareTo(((Role)o).getName());
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
        final Role other = (Role) obj;
        if ((this.role.getName() == null) ? (other.getName() != null) : !this.role.getName().equals(other.getName())) {
            return false;
        }
        if (this.role.getPattern() != other.getPattern() && (this.role.getPattern() == null || !this.role.getPattern().equals(other.getPattern()))) {
            return false;
        }
        if (this.role.getPermissions() != other.getPermissions() && (this.role.getPermissions() == null || !this.role.getPermissions().equals(other.getPermissions()))) {
            return false;
        }
        return true;
    }
}
