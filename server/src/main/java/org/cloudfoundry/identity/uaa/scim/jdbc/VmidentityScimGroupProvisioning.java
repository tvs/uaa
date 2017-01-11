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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.MemberAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.Group;
import com.vmware.identity.idm.GroupDetail;
import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityScimGroupProvisioning implements ScimGroupProvisioning, ScimGroupExternalMembershipManager {

    private final CasIdmClient _idmClient;
    private final Log logger = LogFactory.getLog(VmidentityScimGroupProvisioning.class);

    public VmidentityScimGroupProvisioning(CasIdmClient casIdmClient) {
        this._idmClient = casIdmClient;
    }

    @Override
    public List<ScimGroup> retrieveAll() {
        throw new UnsupportedOperationException();
    }

    @Override
    public ScimGroup retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            String[] parts = id.split("@");
            PrincipalId groupId = new PrincipalId(parts[0], parts[1]);
            Group group = this._idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", id);
            }
            return getScimGroup(group, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Group '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public ScimGroup create(ScimGroup resource) {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            String name = resource.getDisplayName();
            String[] parts = name.split("@");
            if (parts.length > 2) {
                throw new InvalidScimResourceException(String.format("Invalid format for group name '%s'", name));
            } else if (parts.length == 2) {
                if (systemDomain.equalsIgnoreCase(parts[1]) == false) {
                    throw new InvalidScimResourceException("Cannot create groups in external domains.");
                }

                name = parts[0];
            }

            GroupDetail gd = new GroupDetail();
            gd.setDescription(resource.getDescription());
            PrincipalId groupId = this._idmClient.addGroup(tenant, name, gd);
            Group group = this._idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", groupId.toString());
            }
            return getScimGroup(group, tenant, systemDomain);
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(resource.getDisplayName());
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Group '%s' not found in tenant '%s'.", resource.getDisplayName(), VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public ScimGroup update(String id, ScimGroup resource) {
        // TODO impl no op
        return this.retrieve(id);
    }

    @Override
    public ScimGroup delete(String id, int version) {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            String[] parts = id.split("@");
            PrincipalId groupId = new PrincipalId(parts[0], parts[1]);
            Group group = this._idmClient.findGroup(tenant, groupId);

            if (group == null) {
                throw new InvalidPrincipalException("Group not found.", id);
            }
            ScimGroup sg = getScimGroup(group, tenant, systemDomain);
            this._idmClient.deletePrincipal(tenant, groupId.getName());
            return sg;
        } catch (InvalidPrincipalException ex) {
            throw new ScimResourceNotFoundException(id);
        } catch (Exception ex) {
            throw new IllegalStateException(
                    String.format("Group '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public List<ScimGroup> query(String filter) {
        // "displayName eq \"abc\"""
        logger.debug("group flter: " + filter);
        return new ArrayList<ScimGroup>();
    }

    @Override
    public List<ScimGroup> query(String filter, String sortBy, boolean ascending) {
        logger.debug("group flter: " + filter);
        return new ArrayList<ScimGroup>();
    }

    @Override
    public int delete(String filter) {
        throw new UnsupportedOperationException();
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
        // TODO Auto-generated method stub
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
        return this.getExternalGroupMapsByGroupId(groupName, origin);
    }

    @Override
    public void unmapAll(String groupId) throws ScimResourceNotFoundException {
        // TODO Auto-generated method stub
    }

    private static ScimGroup getScimGroup(Group idmGroup, String tenant, String systemDomain) {
        String upn = VmidentityUtils.getPrincipalUpn(idmGroup.getId());
        ScimGroup group = new ScimGroup(upn, upn, tenant);
        group.setDescription(idmGroup.getDetail().getDescription());
        ScimMeta meta = new ScimMeta();
        meta.setVersion(1);
        group.setMeta(meta);
        return group;
    }
}
