package hipaa.access_control

# HIPAA Security Rule § 164.312(a)(1) - Access Control
# Assign a unique name and/or number for identifying and tracking user identity

# Deny IAM users without proper naming convention
deny[msg] {
    input.resource_type == "aws_iam_user"
    user := input.resource_changes[_]
    user.type == "aws_iam_user"
    not starts_with(user.change.after.name, "hipaa-user-")
    msg := sprintf("IAM user '%s' must follow naming convention 'hipaa-user-<id>'", [user.change.after.name])
}

# Deny IAM users without proper path
deny[msg] {
    input.resource_type == "aws_iam_user"
    user := input.resource_changes[_]
    user.type == "aws_iam_user"
    user.change.after.path != "/hipaa-users/"
    msg := sprintf("IAM user '%s' must be in path '/hipaa-users/'", [user.change.after.name])
}

# Deny IAM users without required tags
deny[msg] {
    input.resource_type == "aws_iam_user"
    user := input.resource_changes[_]
    user.type == "aws_iam_user"
    not user.change.after.tags.Control
    msg := sprintf("IAM user '%s' must have 'Control' tag for HIPAA compliance", [user.change.after.name])
}

# Require MFA policy for all IAM users
deny[msg] {
    input.resource_type == "aws_iam_user"
    user := input.resource_changes[_]
    user.type == "aws_iam_user"
    
    # Check if there's a corresponding MFA policy
    mfa_policies := [p | p := input.resource_changes[_]; p.type == "aws_iam_user_policy"; contains(p.change.after.policy, "MultiFactorAuthPresent")]
    count(mfa_policies) == 0
    
    msg := sprintf("IAM user '%s' must have an associated MFA policy", [user.change.after.name])
}