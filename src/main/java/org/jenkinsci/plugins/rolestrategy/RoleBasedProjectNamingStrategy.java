package org.jenkinsci.plugins.rolestrategy;

import com.michelin.cio.hudson.plugins.rolestrategy.MatchingSid;
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
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.regex.Matcher;
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

    private List<Matcher> checkAuthorities(Set<MatchingSid> sids, boolean matchAll) {

        List<Matcher> matchingAuthorities = new ArrayList<>();
        Authentication authentication = Jenkins.getAuthentication();
        for( MatchingSid sid : sids ){
            String principal = (new PrincipalSid(authentication)).getPrincipal();
            Matcher matcher = sid.matches(principal);
            if( principal.equals( sid.getName())|| matcher.matches()){
                matchingAuthorities.add(matcher);
                if( !matchAll) break;
            }
            for(GrantedAuthority ga : authentication.getAuthorities()) {
                String authorityName = (new GrantedAuthoritySid(ga)).getGrantedAuthority();
                matcher = sid.matches(authorityName);
                if( authorityName.equals(sid.getName()) || matcher.matches()){
                    matchingAuthorities.add(matcher);
                    if( !matchAll) break;
                }
            }
        }

        return matchingAuthorities;
    }

    @Override
    public void checkName(String name) throws Failure {
        boolean matches = false;
        ArrayList<String> badList = null;
       AuthorizationStrategy auth = Jenkins.getInstance().getAuthorizationStrategy();
        if (auth instanceof RoleBasedAuthorizationStrategy){
            RoleBasedAuthorizationStrategy rbas = (RoleBasedAuthorizationStrategy) auth;

            //firstly check global role
            SortedMap<Role, Set<MatchingSid>> gRole = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.GLOBAL);
            boolean hasGlobalAuth = false;
            boolean isAdmin = false;
            for (SortedMap.Entry<Role, Set<MatchingSid>> entry: gRole.entrySet()){
                List<Matcher> matchingAuthorities = checkAuthorities(entry.getValue(), false);
                if( matchingAuthorities.size() > 0) {
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
                SortedMap<Role, Set<MatchingSid>> roles = rbas.getGrantedRoles(RoleBasedAuthorizationStrategy.PROJECT);
                badList = new ArrayList<>(roles.size());
                for (SortedMap.Entry<Role, Set<MatchingSid>> entry : roles.entrySet()) {

                    if (hasGlobalAuth) {
                        Role key = entry.getKey();
                        if (key.hasPermission(Item.CREATE)) {
                            String namePattern = key.getPattern().toString();
                            if (StringUtils.isNotBlank(namePattern) && StringUtils.isNotBlank(name)) {
                                Pattern pattern = Pattern.compile(namePattern);
                                Matcher matcher = pattern.matcher(name);
                                List<Matcher> matchingAuthorities = checkAuthorities(entry.getValue(), matcher.groupCount() > 0);
                                if (matchingAuthorities.size() > 0 && hasGlobalAuth) {
                                    if (matcher.groupCount() == 0) {
                                        if (matcher.matches()) {
                                            matches = true;
                                        } else {
                                            badList.add(namePattern);
                                        }
                                    } else {
                                        if (matcher.matches()) {
                                            String catchingGroup = matcher.group(1);
                                            for (Matcher nextMatcher : matchingAuthorities) {
                                                if (nextMatcher.groupCount() > 0 && nextMatcher.group(1).equals(catchingGroup)) {
                                                    matches = true;
                                                    break;
                                                }
                                            }
                                            if (!matches) {
                                                badList.add(namePattern);
                                            }
                                        } else {
                                            badList.add(namePattern);
                                        }
                                    }
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
