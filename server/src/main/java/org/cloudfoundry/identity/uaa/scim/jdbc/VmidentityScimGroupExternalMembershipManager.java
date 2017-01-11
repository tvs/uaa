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
import java.util.List;

import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityScimGroupExternalMembershipManager implements ScimGroupExternalMembershipManager {

    private final CasIdmClient _idmClient;

    public VmidentityScimGroupExternalMembershipManager(CasIdmClient casIdmClient) {
        this._idmClient = casIdmClient;
    }

    @Override
    public ScimGroupExternalMember mapExternalGroup(String groupId, String externalGroup, String origin)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {
        // TODO proper impl
        ScimGroupExternalMember mem = new ScimGroupExternalMember(groupId, externalGroup);
        mem.setOrigin(origin);
        return mem;
    }

    @Override
    public ScimGroupExternalMember unmapExternalGroup(String groupId, String externalGroup, String origin)
            throws ScimResourceNotFoundException {
        // TODO proper impl
        ScimGroupExternalMember mem = new ScimGroupExternalMember(groupId, externalGroup);
        mem.setOrigin(origin);
        return mem;
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(String groupId, String origin)
            throws ScimResourceNotFoundException {
        return new ArrayList<ScimGroupExternalMember>();
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(String externalGroup, String origin)
            throws ScimResourceNotFoundException {
        return new ArrayList<ScimGroupExternalMember>();
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(String groupName, String origin)
            throws ScimResourceNotFoundException {
        return new ArrayList<ScimGroupExternalMember>();
    }

    @Override
    public void unmapAll(String groupId) throws ScimResourceNotFoundException {
        // TODO Auto-generated method stub

    }

}
