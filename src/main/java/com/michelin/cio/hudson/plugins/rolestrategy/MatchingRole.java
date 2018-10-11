package com.michelin.cio.hudson.plugins.rolestrategy;

import hudson.security.Permission;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MatchingRole extends Role {

    Role role;
    Matcher matcher;


    public MatchingRole(Role role, Matcher matcher){
        this.role = role;
        this.matcher = matcher;
    }
/*
    public MatchingRole(String name, Set<Permission> permissions) {
        role = new Role(name, permissions);
    }

    public MatchingRole(String name, String pattern, Set<Permission> permissions) {
        role = new Role(name, pattern, permissions);
    }

    public MatchingRole(@Nonnull String name, @CheckForNull String pattern, @CheckForNull Set<String> permissionIds, @CheckForNull String description) {
        role = new Role(name, pattern, permissionIds, description);
    }

    public MatchingRole(String name, Pattern pattern, Set<Permission> permissions, @CheckForNull String description) {
        role = new Role(name, pattern, permissions, description);
    }
    */

    public final String getName(){
        return role.getName();
    }

    @Override
    public Pattern getPattern() {
        return role.getPattern();
    }

    @Override
    public Set<Permission> getPermissions() {
        return role.getPermissions();
    }

    @CheckForNull
    @Override
    public String getDescription() {
        return role.getDescription();
    }

    @Override
    public Boolean hasPermission(Permission permission) {
        return role.hasPermission(permission);
    }

    @Override
    public Boolean hasAnyPermission(Set<Permission> permissions) {
        return role.hasAnyPermission(permissions);
    }

    @Override
    public int compareTo(Object o) {
        return role.compareTo(o);
    }

    @Override
    public int hashCode() {
        return role.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if ( !(obj instanceof MatchingRole) )  {
            return false;
        }
        final Role other = (Role) obj;
        if ((this.getName() == null) ? (other.getName() != null) : !this.getName().equals(other.getName())) {
            return false;
        }
        if (this.getPattern() != other.getPattern() && (this.getPattern() == null || !this.getPattern().equals(other.getPattern()))) {
            return false;
        }
        if (this.getPermissions() != other.getPermissions() && (this.getPermissions() == null || !this.getPermissions().equals(other.getPermissions()))) {
            return false;
        }
        return true;
    }


}
