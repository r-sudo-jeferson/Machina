permit(
    principal,
    action == Action::"context.read",
    resource == PlatformContext::"active"
) when {
    context.membership_status == "active" &&
    context.starter_role == "owner"
};

permit(
    principal,
    action == Action::"context.read",
    resource == PlatformContext::"active"
) when {
    context.membership_status == "active" &&
    context.starter_role == "member"
};

permit(
    principal,
    action == Action::"tenant.switch",
    resource is Tenant
) when {
    context.membership_status == "active" &&
    context.starter_role == "owner"
};

permit(
    principal,
    action == Action::"tenant.switch",
    resource is Tenant
) when {
    context.membership_status == "active" &&
    context.starter_role == "member"
};
