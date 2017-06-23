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
package org.cloudfoundry.identity.uaa.approval;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import com.vmware.identity.idm.client.CasIdmClient;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class VmidentityApprovalStore implements ApprovalStore, ApplicationEventPublisherAware {
    private final Log logger = LogFactory.getLog(VmidentityApprovalStore.class);

    private ApplicationEventPublisher applicationEventPublisher;
    private CasIdmClient client;
    private boolean handleRevocationsAsExpiry = false;

    public VmidentityApprovalStore(CasIdmClient client) {
        this.client = client;
    }

    public void setHandleRevocationsAsExpiry(boolean handleRevocationsAsExpiry) {
        this.handleRevocationsAsExpiry = handleRevocationsAsExpiry;
    }

    @Override
    public boolean addApproval(Approval approval) {
        try {
            String tenant = VmidentityUtils.getTenantName(client);
            Approval added = convertToUaaApproval(client.addApproval(tenant, convertToIdmApproval(approval)));

            if (added != null) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                publish(new ApprovalModifiedEvent(added, authentication));
                return true;
            } else {
                return false;
            }
        } catch (Exception ex) {
            logger.error("Adding an approval failed", ex);
            throw new VmidentityDataAccessException("Unable to add approval");
        }
    }

    @Override
    public boolean revokeApproval(Approval approval) {
        return revokeApprovals(String.format("user_id eq \"%s\" and client_id eq \"%s\" and scope eq \"%s\"", approval.getUserId(), approval.getClientId(), approval.getScope()));
    }

    @Override
    public boolean revokeApprovals(String filter) {
        try {
            String tenant = VmidentityUtils.getTenantName(client);
            if (handleRevocationsAsExpiry) {
                Collection<com.vmware.identity.idm.Approval> revoked = client.getApprovals(tenant, filter);
                Calendar calendar = Calendar.getInstance();
                calendar.add(Calendar.SECOND, -1);
                Date now = new Date();

                for (com.vmware.identity.idm.Approval approval : revoked) {
                    approval.setExpiresAt(calendar.getTime()).setLastUpdatedAt(now);
                    client.updateApproval(tenant, approval);
                }
            } else {
                Collection<com.vmware.identity.idm.Approval> revoked = client.revokeApprovals(tenant, filter);
                logger.debug(String.format("Revoked [%d] approvals matching filter [%s]", revoked.size(), filter));
            }
        } catch (Exception ex) {
            logger.error("Error revoking approvals with filter: " + filter, ex);
            throw new VmidentityDataAccessException("Error revoking approvals with filter: " + filter);
        }
        return true;
    }

    @Override
    public List<Approval> getApprovals(String filter) {
        try {
            String tenant = VmidentityUtils.getTenantName(client);
            Collection<com.vmware.identity.idm.Approval> approvals = client.getApprovals(tenant, filter);
            return convertToUaaApproval(approvals);
        } catch (Exception ex) {
            logger.error("Error getting approvals with filter: " + filter, ex);
            throw new VmidentityDataAccessException("Unable to get approvals by filter: " + filter);
        }
    }

    @Override
    public List<Approval> getApprovals(String userId, String clientId) {
        return getApprovals(String.format("user_id eq \"%s\" and client_id eq \"%s\"", userId, clientId));
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    private void publish(ApplicationEvent event) {
        if (this.applicationEventPublisher != null) {
            this.applicationEventPublisher.publishEvent(event);
        }
    }

    private static com.vmware.identity.idm.Approval convertToIdmApproval(Approval approval) {
        return new com.vmware.identity.idm.Approval()
                .setUserId(approval.getUserId())
                .setClientId(approval.getClientId())
                .setScope(approval.getScope())
                .setStatus(com.vmware.identity.idm.Approval.ApprovalStatus.valueOf(approval.getStatus().toString()))
                .setExpiresAt(approval.getExpiresAt())
                .setLastUpdatedAt(approval.getLastUpdatedAt());
    }

    private static List<Approval> convertToUaaApproval(Collection<com.vmware.identity.idm.Approval> approvals) {
        List<Approval> uaaApprovals = new ArrayList<>(approvals.size());
        for (com.vmware.identity.idm.Approval approval : approvals) {
            uaaApprovals.add(convertToUaaApproval(approval));
        }
        return uaaApprovals;
    }

    private static Approval convertToUaaApproval(com.vmware.identity.idm.Approval approval) {
        return new Approval()
                .setUserId(approval.getUserId())
                .setClientId(approval.getClientId())
                .setScope(approval.getScope())
                .setStatus(Approval.ApprovalStatus.valueOf(approval.getStatus().toString()))
                .setExpiresAt(approval.getExpiresAt())
                .setLastUpdatedAt(approval.getLastUpdatedAt());
    }
}
