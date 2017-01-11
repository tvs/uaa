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
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class VmidentityApprovalStore implements ApprovalStore, ApplicationEventPublisherAware {

    // in memory for now
    private List<Approval> _approvals;

    private final Log logger = LogFactory.getLog(VmidentityApprovalStore.class);

    // USER_APPROVALS_FILTER_TEMPLATE = "user_id eq \"%s\""
    // USER_FILTER_TEMPLATE = "user_id eq \"%s\"";
    // USER_AND_CLIENT_FILTER_TEMPLATE = "user_id eq \"%s\" and client_id eq \"%s\"";

    private final Object _lock;

    private ApplicationEventPublisher _applicationEventPublisher;

    public VmidentityApprovalStore() {
        this._approvals = new ArrayList<Approval>();
        this._lock = new Object();
    }

    @Override
    public boolean addApproval(Approval approval) {
        synchronized (this._lock) {
            this._approvals.add(approval);
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        publish(new ApprovalModifiedEvent(approval, authentication));
        return true;
    }

    @Override
    public boolean revokeApproval(Approval approval) {
        synchronized (this._lock) {
            this._approvals.remove(approval);
        }
        return false;
    }

    @Override
    public boolean revokeApprovals(String filter) {
        logger.debug(String.format("revokeApprovals: filter='%s'", filter));
        String userId = getUserId(filter);
        String clientId = getClientId(filter);

        synchronized (this._lock) {
            for (Approval a : this.internalGetApprovals(userId, clientId)) {
                this._approvals.remove(a);
            }
        }
        return true;
    }

    @Override
    public List<Approval> getApprovals(String filter) {
        logger.debug(String.format("getApprovals: filter='%s'", filter));
        String userId = getUserId(filter);
        String clientId = getClientId(filter);
        return this.getApprovals(userId, clientId);
    }

    @Override
    public List<Approval> getApprovals(String userId, String clientId) {
        synchronized (this._lock) {
            return this.internalGetApprovals(userId, clientId);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this._applicationEventPublisher = applicationEventPublisher;
    }

    private void publish(ApplicationEvent event) {
        if (this._applicationEventPublisher != null) {
            this._applicationEventPublisher.publishEvent(event);
        }
    }

    public List<Approval> internalGetApprovals(String userId, String clientId) {
        if (userId == null && clientId == null) {
            throw new UnsupportedOperationException();
        }
        ArrayList<Approval> approvals = new ArrayList<Approval>();
        for (Approval a : this._approvals) {
            if ((userId == null) || userId.equals(a.getUserId())
                    &&
                    ((clientId == null) || (clientId.equals(a.getClientId())))) {
                approvals.add(a);
            }
        }

        return approvals;
    }

    private static String getUserId(String filter) {
        // todo: use proper impl
        // "user_id eq \"%s\""
        // "user_id eq \"%s\" and client_id eq \"%s\""
        return getId(filter, "user_id");
    }

    private static String getClientId(String filter) {
        // todo: use proper impl
        // "user_id eq \"%s\" and client_id eq \"%s\""
        return getId(filter, "client_id");
    }

    private static String getId(String filter, String attribute) {
        String id = null;
        // "attr eq \"%s\"
        String expr = attribute + " eq ";
        int index = filter.indexOf(expr);
        if (index > -1) {
            int index1 = filter.indexOf("\"", index + expr.length() - 1);
            if (index1 > -1) {
                int index2 = filter.indexOf("\"", index1 + 1);
                if ((index2 > -1) && (index1 < index2)) {
                    id = filter.substring(index1 + 1, index2);
                }
            }
        }
        return id;
    }
}
