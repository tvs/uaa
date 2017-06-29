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

import java.util.Collections;
import java.util.List;

import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;

import com.vmware.identity.idm.client.CasIdmClient;

/**
 * WARNING: {@code VmidentityScimGroupExternalMembershipManager} is largely unimplemented at this point
 * IDM doesn't have a mechanism to perform this mapping of UAA Group (scope) to another external group.
 * In general IDM operates on the notion of group-as-scope, so the best analogue we have is to add an
 * external group as a member of our groups, thereby creating a nested membership for those external users.
 * This doesn't function quite exactly the same, however, as it's not clear that external groups are supported
 * in this manner.
 *
 * TODO Implement VmidentityScimGroupExternalMembershipManager
 */
public class VmidentityScimGroupExternalMembershipManager implements ScimGroupExternalMembershipManager {

    private final CasIdmClient idmClient;

    public VmidentityScimGroupExternalMembershipManager(CasIdmClient idmClient) {
        this.idmClient = idmClient;
    }

    @Override
    public ScimGroupExternalMember mapExternalGroup(String groupId, String externalGroup, String origin)
            throws ScimResourceNotFoundException, MemberAlreadyExistsException {
        ScimGroupExternalMember mem = new ScimGroupExternalMember(groupId, externalGroup);
        mem.setOrigin(origin);
        return mem;
    }

    @Override
    public ScimGroupExternalMember unmapExternalGroup(String groupId, String externalGroup, String origin)
            throws ScimResourceNotFoundException {
        ScimGroupExternalMember mem = new ScimGroupExternalMember(groupId, externalGroup);
        mem.setOrigin(origin);
        return mem;
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupId(String groupId, String origin)
            throws ScimResourceNotFoundException {
        return Collections.emptyList();
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByExternalGroup(String externalGroup, String origin)
            throws ScimResourceNotFoundException {
        return Collections.emptyList();
    }

    @Override
    public List<ScimGroupExternalMember> getExternalGroupMapsByGroupName(String groupName, String origin)
            throws ScimResourceNotFoundException {
        return Collections.emptyList();
    }

    @Override
    public void unmapAll(String groupId) throws ScimResourceNotFoundException {
    }

    @Override
    public List<ScimGroupExternalMember> query(String filter) {
        return Collections.emptyList();
    }

    @Override
    public List<ScimGroupExternalMember> query(String filter, String sortBy, boolean ascending) {
        return Collections.emptyList();
    }

    @Override
    public int delete(String filter) {
        return 0;
    }

}
