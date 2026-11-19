namespace VulnTracker.Api.Authorization;

public static class AppRoles{
    public const string Pm = "PM";
    public const string Analyst = "Analyst";
    public const string Developer = "Developer";
    public const string Auditor = "Auditor";
}

public static class AuthPolicies{
    public const string CanViewFindings = "CanViewFindings";
    public const string CanCreateFindings = "CanCreateFindings";
    public const string CanAssignFindings = "CanAssignFindings";
    public const string CanSetSla = "CanSetSla";
    public const string CanManageUsers = "CanManageUsers";
    public const string CanReadAuditLogs = "CanReadAuditLogs";
    public const string CanUpdateFinding = "CanUpdateFinding";
}