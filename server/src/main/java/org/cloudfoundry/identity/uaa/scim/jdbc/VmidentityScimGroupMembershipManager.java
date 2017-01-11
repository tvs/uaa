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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Role;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMembershipManager;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberNotFoundException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityScimGroupMembershipManager implements ScimGroupMembershipManager {

    private final CasIdmClient _idmClient;

    public VmidentityScimGroupMembershipManager(CasIdmClient casIdmClient) {
        this._idmClient = casIdmClient;
    }

    @Override
    public List<ScimGroupMember> query(String filter) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ScimGroupMember> query(String filter, String sortBy, boolean ascending) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int delete(String filter) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimGroupMember addMember(String groupId, ScimGroupMember member)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ScimGroupMember> getMembers(String groupId, String filter, boolean includeEntities)
            throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ScimGroupMember> getMembers(String groupId, Role permission) throws ScimResourceNotFoundException {
        // TODO Auto-generated method stub
        return new ArrayList<ScimGroupMember>();
    }

    @Override
    public Set<ScimGroup> getGroupsWithMember(String memberId, boolean transitive)
            throws ScimResourceNotFoundException {
        // TODO Auto-generated method stub
        // getdirect/getnested parent groups
        return new HashSet<ScimGroup>();
    }

    @Override
    public ScimGroupMember getMemberById(String groupId, String memberId)
            throws ScimResourceNotFoundException, MemberNotFoundException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ScimGroupMember updateMember(String groupId, ScimGroupMember member) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ScimGroupMember> updateOrAddMembers(String groupId, List<ScimGroupMember> members) {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimGroupMember removeMemberById(String groupId, String memberId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<ScimGroupMember> removeMembersByGroupId(String groupId) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<ScimGroup> removeMembersByMemberId(String memberId) throws ScimResourceNotFoundException {
        throw new UnsupportedOperationException();
    }

    private static ScimGroupMember createGroupMembership(String memberId, ScimGroupMember.Type memberType) {
        List<ScimGroupMember.Role> roles = new ArrayList<ScimGroupMember.Role>();
        roles.add(ScimGroupMember.Role.MEMBER);
        ScimGroupMember sgm = new ScimGroupMember(memberId, memberType, roles);
        sgm.setOrigin(OriginKeys.UAA);
        return sgm;
    }
}
