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
