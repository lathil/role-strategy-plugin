package org.jenkinsci.plugins.rolestrategy;

import com.michelin.cio.hudson.plugins.rolestrategy.Messages;
import com.michelin.cio.hudson.plugins.rolestrategy.Role;
import com.michelin.cio.hudson.plugins.rolestrategy.RoleBasedAuthorizationStrategy;
import hudson.Extension;
import hudson.model.Failure;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.security.AuthorizationStrategy;
import jenkins.model.Jenkins;
import jenkins.model.ProjectNamingStrategy;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.acls.sid.GrantedAuthoritySid;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Set;
import java.util.SortedMap;
import java.util.regex.Pattern;

/**
 * @author Kanstantsin Shautsou
 * @since 2.2.0
 */
public class RoleBasedProjectNamingStrategy extends ProjectNamingStrategy implements Serializable {

    private static final long serialVersionUID = 1L;

    private final boolean forceExistingJobs;

    @DataBoundConstructor
    public RoleBasedProjectNamingStrategy(boolean forceExistingJobs) {
        this.forceExistingJobs = forceExistingJobs;
    }

    private boolean checkAuthorities(Set<String> sids) {
        Authentication authentication = Jenkins.getAuthentication();
        for( String sid : sids ){
            String principal = (new PrincipalSid(authentication)).getPrincipal();
            if( principal.equals( sid )){
                return true;
            }
            for(GrantedAuthority ga : authentication.getAuthorities()) {
                String authorityName = (new GrantedAuthoritySid(ga)).getGrantedAuthority();
                if( authorityName.equals(sid)){
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public void checkName(String name) throws Failure {
        boolean matches = false;
        ArrayList<String> badList = null;
        AuthorizationStrategy auth = Jenkins.getActiveInstance().getAuthorizationStrategy();
        if (auth instanceof RoleBasedAuthorizationStrategy){
            RoleBasedAuthorizationStrategy rbas = (RoleBasedAuthorizationStrategy) auth;
            //firstly check global role
            SortedMap<Role, Set<String>> gRole = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL);
            boolean hasGlobalAuth = false;
            boolean isAdmin = false;
            for (SortedMap.Entry<Role, Set<String>> entry: gRole.entrySet()){
                if( checkAuthorities(entry.getValue())) {
                    if (entry.getKey().hasPermission(Item.CREATE)) {
                        hasGlobalAuth = true;
                    }
                    if( entry.getKey().hasPermission(Hudson.ADMINISTER)){
                        isAdmin = true;
                    }
                }
            }

            if( isAdmin) {
                // admin have right to name projects the way they want.
                matches = true;
            } else {
                // check project role with pattern
                SortedMap<Role, Set<String>> roles = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.PROJECT);
                badList = new ArrayList<>(roles.size());
                for (SortedMap.Entry<Role, Set<String>> entry : roles.entrySet()) {
                    if (checkAuthorities(entry.getValue()) && hasGlobalAuth) {
                        Role key = entry.getKey();
                        if (key.hasPermission(Item.CREATE)) {
                            String namePattern = key.getPattern().toString();
                            if (StringUtils.isNotBlank(namePattern) && StringUtils.isNotBlank(name)) {
                                if (Pattern.matches(namePattern, name)) {
                                    matches = true;
                                } else {
                                    badList.add(namePattern);
                                }
                            }
                        }
                    }
                }
            }

        }
        if (!matches) {
            String error;
            if (badList != null && !badList.isEmpty())
                //TODO beatify long outputs?
                error = Messages.RoleBasedProjectNamingStrategy_JobNameConventionNotApplyed(name, badList.toString());
            else
                error = Messages.RoleBasedProjectNamingStrategy_NoPermissions();
            throw new Failure(error);
        }
    }

    @Override
    public boolean isForceExistingJobs() {
        return forceExistingJobs;
    }

    @Extension
    public static final class DescriptorImpl extends ProjectNamingStrategyDescriptor {

        @Override
        public String getDisplayName() {
            return Messages.RoleBasedAuthorizationStrategy_DisplayName();
        }

    }
}
