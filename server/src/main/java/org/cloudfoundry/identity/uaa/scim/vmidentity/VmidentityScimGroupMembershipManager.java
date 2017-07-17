/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.scim.vmidentity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Role;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.Group;
import com.vmware.identity.idm.InvalidArgumentException;
import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PersonUser;
import com.vmware.identity.idm.Principal;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityScimGroupMembershipManager implements ScimGroupMembershipManager {

    public static final String MEMBERSHIP_FIELDS = "group_id,member_id,member_type,authorities,added,origin";

    private final Log logger = LogFactory.getLog(VmidentityScimGroupMembershipManager.class);
    private final CasIdmClient idmClient;

    public VmidentityScimGroupMembershipManager(CasIdmClient idmClient) {
        this.idmClient = idmClient;
    }

    @Override
    public List<ScimGroupMember> query(String filter) {
        throw new UnsupportedOperationException("Vmidentity does not support proper filtering on group membership");
    }

    @Override
    public List<ScimGroupMember> query(String filter, String sortBy, boolean ascending) {
        throw new UnsupportedOperationException("Vmidentity does not support proper filtering on group membership");
    }

    @Override
    public int delete(String filter) {
        throw new UnsupportedOperationException("Vmidentity does not support deleting group membership by filters");
    }

    @Override
    public ScimGroupMember addMember(String groupId, ScimGroupMember member)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            Group group = this.idmClient.findGroup(tenant, groupId);
            if (!systemDomain.equalsIgnoreCase(group.getId().getDomain())) {
                logger.error("Cannot modify group membership for groups in non-system domain. " + groupId);
                throw new InvalidScimResourceException(
                        "Cannot modify group membership for groups in non-system domain.");
            }

            Principal idmPrincipal = null;
            if (member.getType() == ScimGroupMember.Type.USER) {
                idmPrincipal = this.idmClient.findUser(tenant, member.getMemberId());
                if (idmPrincipal != null) {
                    this.idmClient.addUserToGroup(tenant, idmPrincipal.getId(), group.getName());
                } else {
                    logger.error("user not found  " + member.getMemberId());
                    throw new ScimResourceNotFoundException("User not found: " + member.getMemberId());
                }
            } else if (member.getType() == ScimGroupMember.Type.GROUP) {
                idmPrincipal = this.idmClient.findGroup(tenant, member.getMemberId());
                if (idmPrincipal != null) {
                    this.idmClient.addGroupToGroup(tenant, idmPrincipal.getId(), group.getName());
                } else {
                    logger.error("group not found  " + member.getMemberId());
                    throw new ScimResourceNotFoundException("Group not found: " + member.getMemberId());
                }
            } else {
                throw new InvalidArgumentException(String.format("Invalid ScimMemberType '%s'", member.getType()));
            }

            return member;
        } catch (com.vmware.identity.idm.MemberAlreadyExistException ex) {
            logger.debug(String.format("Scim group member already exists '%s'.", member.getMemberId()));
            throw new MemberAlreadyExistsException(
                    String.format("Scim group member already exists '%s'.", member.getMemberId()));
        } catch (InvalidPrincipalException ex) {
            logger.debug(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
            throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
        } catch (Exception ex) {
            logger.debug(String.format("addMember '%s', '%s' failed", groupId, member.getMemberId()), ex);
            throw new IllegalStateException(String.format("addMember '%s', '%s' ", groupId, member.getMemberId()), ex);
        }
    }

    @Override
    public List<ScimGroupMember> getMembers(String groupId, String filter, boolean includeEntities)
            throws ScimResourceNotFoundException {
        // TODO: Figure out how to filter these...
        return this.getMembers(groupId, Role.MEMBER);
    }

    @Override
    public List<ScimGroupMember> getMembers(String groupId, Role permission) throws ScimResourceNotFoundException {
        try {
            ArrayList<ScimGroupMember> members = new ArrayList<ScimGroupMember>();
            // TODO:rationalize permission meaning
            if (permission == ScimGroupMember.Role.MEMBER) {
                String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
                String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
                Group group = this.idmClient.findGroup(tenant, groupId);

                // TODO: limits ...
                Set<Group> groups = this.idmClient.findGroupsByNameInGroup(tenant, group.getId(), "", -1);
                Set<PersonUser> users = this.idmClient.findPersonUsersByNameInGroup(tenant, group.getId(), "", -1);

                if (groups != null) {
                    for (Group g : groups) {
                        members.add(createGroupMembership(g.getId().getUPN(), ScimGroupMember.Type.GROUP,
                                VmidentityUtils.getOriginForDomain(tenant, g.getDomain(), systemDomain, this.idmClient)));
                    }
                }

                if (users != null) {
                    for (PersonUser user : users) {
                        members.add(createGroupMembership(user.getId().getUPN(), ScimGroupMember.Type.USER,
                                VmidentityUtils.getOriginForDomain(tenant, group.getDomain(), systemDomain, this.idmClient)));
                    }
                }
            }

            return members;
        } catch (InvalidPrincipalException ex) {
            logger.debug(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
            throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
        } catch (Exception ex) {
            logger.debug(String.format("getMembers '%s', '%s' ", groupId, permission.name()), ex);
            throw new IllegalStateException(String.format("getMembers '%s', '%s' ", groupId, permission.name()), ex);
        }
    }

    @Override
    public Set<ScimGroup> getGroupsWithMember(String memberId, boolean transitive)
            throws ScimResourceNotFoundException {
        try {
            HashSet<ScimGroup> members = new HashSet<ScimGroup>();
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);

            PrincipalId principalId = VmidentityUtils.getPrincipalId(memberId);
            Set<Group> groups = null;

            if (transitive) {
                groups = this.idmClient.findNestedParentGroups(tenant, principalId);
            } else {
                groups = this.idmClient.findDirectParentGroups(tenant, principalId);
            }

            if (groups != null) {
                for (Group g : groups) {
                    members.add(VmidentityScimGroupProvisioning.getScimGroup(g, tenant, systemDomain));
                }
            }

            return members;
        } catch (InvalidPrincipalException ex) {
            logger.debug(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
            throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
        } catch (Exception ex) {
            logger.debug(String.format("getGroupsWithMember '%s', '%s' ", memberId, transitive ? "true" : "false"), ex);
            throw new IllegalStateException(
                    String.format("getGroupsWithMember '%s', '%s' ", memberId, transitive ? "true" : "false"), ex);
        }
    }

    @Override
    public ScimGroupMember getMemberById(String groupId, String memberId)
            throws ScimResourceNotFoundException, MemberNotFoundException {
        // todo: implement better perf
        List<ScimGroupMember> groupMembers = this.getMembers(groupId, ScimGroupMember.Role.MEMBER);
        for (ScimGroupMember gm : groupMembers) {
            if (gm.getMemberId().equals(memberId)) {
                return gm;
            }
        }

        logger.debug(String.format("Scim resource not found '%s' '%s'.", groupId, memberId));
        throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s' '%s'.", groupId, memberId));
    }

    @Override
    public ScimGroupMember updateMember(String groupId, ScimGroupMember member) {
        // todo : noop at the moment
        return member;
    }

    @Override
    public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) {
        // todo impl with better perf
        for (ScimGroupMember gm : members) {
            try {
                this.addMember(groupId, gm);
            } catch (MemberAlreadyExistsException ex) {
                // to do: noop->update
            }
        }

        // todo: should we return all? or only original input
        return this.getMembers(groupId, ScimGroupMember.Role.MEMBER);
    }

    @Override
    public ScimGroupMember removeMemberById(String groupId, String memberId) {
        try {
            ScimGroupMember gm = null;
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            Group group = this.idmClient.findGroup(tenant, groupId);

            if (!systemDomain.equalsIgnoreCase(group.getId().getDomain())) {
                logger.error("Cannot modify group membership for groups in non-system domain. " + groupId);
                throw new InvalidScimResourceException("Cannot modify group membership for groups in non-system domain.");
            }
            // todo: we need a findPrincipal in idm client....
            PrincipalId id = VmidentityUtils.getPrincipalId(memberId);
            ScimGroupMember.Type type = ScimGroupMember.Type.USER;

            Principal principal = null;
            try {
                principal = this.idmClient.findGroup(tenant, id);
            } catch (InvalidPrincipalException ex) {
            }

            if (principal != null) {
                type = ScimGroupMember.Type.GROUP;
            }

            if (this.idmClient.removeFromLocalGroup(tenant, id, group.getName())) {
                gm = createGroupMembership(memberId, type, VmidentityUtils.getOriginForDomain(tenant, group.getDomain(), systemDomain, this.idmClient));
            }

            return gm;
        } catch (InvalidPrincipalException ex) {
            logger.debug(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
            throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
        } catch (Exception ex) {
            logger.debug(String.format("addMember '%s', '%s' ", groupId, memberId), ex);
            throw new IllegalStateException(String.format("addMember '%s', '%s' ", groupId, memberId), ex);
        }
    }

    @Override
    public List<ScimGroupMember> removeMembersByGroupId(String groupId) throws ScimResourceNotFoundException {
        // todo: reimplement for better perf
        try {
            List<ScimGroupMember> modifiedList = new ArrayList<ScimGroupMember>();
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient);
            Group group = this.idmClient.findGroup(tenant, groupId);
            if (!systemDomain.equalsIgnoreCase(group.getId().getDomain())) {
                logger.error("Cannot modify group membership for groups in non-system domain. " + groupId);
                throw new InvalidScimResourceException(
                        "Cannot modify group membership for groups in non-system domain.");
            }

            List<ScimGroupMember> members = this.getMembers(groupId, ScimGroupMember.Role.MEMBER);
            ScimGroupMember removed = null;
            for (ScimGroupMember member : members) {
                removed = this.removeMemberById(groupId, member.getMemberId());

                if (removed != null) {
                    modifiedList.add(removed);
                }
            }

            return modifiedList;
        } catch (ScimResourceNotFoundException ex) {
            throw ex;
        } catch (InvalidPrincipalException ex) {
            logger.debug(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
            throw new ScimResourceNotFoundException(String.format("Scim resource not found '%s'.", ex.getPrincipal()));
        } catch (Exception ex) {
            logger.debug(String.format("removeMembersByGroupId '%s' ", groupId), ex);
            throw new IllegalStateException(String.format("removeMembersByGroupId '%s' ", groupId), ex);
        }
    }

    @Override
    public Set<ScimGroup> removeMembersByMemberId(String memberId) throws ScimResourceNotFoundException {
        Set<ScimGroup> groups = this.getGroupsWithMember(memberId, false);
        HashSet<ScimGroup> modifiedGroups = new HashSet<ScimGroup>();
        String tenant = null;
        String systemDomain = null;

        try {
            tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            systemDomain = VmidentityUtils.getSystemDomain(tenant, this.idmClient).toUpperCase(Locale.ENGLISH);
        } catch (Exception ex) {
            logger.debug(String.format("removeMembersByMemberId '%s' ", memberId));
            throw new IllegalStateException(String.format("removeMembersByMemberId '%s' ", memberId), ex);
        }

        for (ScimGroup g : groups) {
            if (g.getId().toUpperCase(Locale.ENGLISH).endsWith(systemDomain)) {
                if (this.removeMemberById(g.getId(), memberId) != null) {
                    modifiedGroups.add(g);
                }
            }
        }

        return modifiedGroups;
    }

    private static ScimGroupMember createGroupMembership(String memberId, ScimGroupMember.Type memberType, String origin) {
        ScimGroupMember sgm = new ScimGroupMember(memberId, memberType, ScimGroupMember.GROUP_MEMBER);
        sgm.setOrigin(origin);
        return sgm;
    }
}
