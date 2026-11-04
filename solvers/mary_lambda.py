"""M.A.R.Y Had a Little Lambda: offline IAM trust + policy audit.

The original Terraform grants devopsadmin IAM read/Lambda discovery and
GetFunction but no direct SSM read. Its Lambda role trusts both AWS Lambda
and the devopsadmin IAM principal, while the role policy permits tagged SSM
GetParameter. This program extracts balanced original Terraform blocks and
builds a synthetic effective-permission graph. It never loads AWS keys,
calls AWS, assumes a real role or decrypts any actual challenge parameter.
"""
import argparse
import re
from dataclasses import dataclass
from pathlib import Path


def balanced_block(source: str, keyword: str, name: str) -> str:
    if keyword not in ("resource", "data"):
        raise ValueError("Only Terraform resource/data blocks can be read")
    pattern = (r'\b' + keyword + r'\s+"([^"]+)"\s+"'
               + re.escape(name) + r'"\s*\{')
    found = re.search(pattern, source)
    if not found:
        raise ValueError("Missing original Terraform block " + name)
    start = found.end()
    depth = 1
    i = start
    quote = False
    escaped = False
    while i < len(source) and depth:
        char = source[i]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
        elif char == '"':
            quote = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth:
        raise ValueError("Unbalanced original Terraform block")
    return source[start:i-1]


def policy_actions(block: str) -> set[str]:
    return set(re.findall(r'"((?:iam|lambda|ssm|sts|logs):[A-Za-z*]+)"', block))


@dataclass(frozen=True)
class PermissionAudit:
    user_actions: frozenset[str]
    role_actions: frozenset[str]
    user_trusted_by_lambda_role: bool
    ssm_is_tag_conditioned: bool
    ssm_parameter_is_challenge_tagged: bool
    direct_getparameter: bool
    assume_role_then_getparameter: bool


def audit_terraform(source: str) -> PermissionAudit:
    user = balanced_block(source, "data", "devopsadmin_policy")
    role = balanced_block(source, "data", "lambda_role_policy")
    trust = balanced_block(source, "data", "lambda_assume_role_policy")
    parameter = balanced_block(source, "resource", "db_secret")
    provider = re.search(r'provider\s+"aws"\s*\{[\s\S]*?default_tags\s*\{\s*tags\s*=\s*\{\s*Challenge\s*=\s*var\.challenge_name', source)
    if not provider:
        raise ValueError("Original AWS provider challenge default tags missing")
    a_user = policy_actions(user)
    a_role = policy_actions(role)
    needs = {"iam:ListUserPolicies", "iam:GetUserPolicy",
             "lambda:ListFunctions", "lambda:GetFunction", "iam:GetRole"}
    if not needs.issubset(a_user):
        raise ValueError("Original devops user permissions changed")
    if "ssm:GetParameter" not in a_role:
        raise ValueError("Original Lambda role no longer grants SSM GetParameter")
    if 'aws:ResourceTag/Challenge' not in role or 'values   = [var.challenge_name]' not in role:
        raise ValueError("Original tagged SSM permission condition missing")
    if 'value       = var.flag' not in parameter or '"SecureString"' not in parameter:
        raise ValueError("Expected encrypted original flag parameter")
    if '"sts:AssumeRole"' not in trust:
        raise ValueError("Original Lambda role trust lacks sts:AssumeRole")
    trusted = (
        'identifiers = [aws_iam_user.devopsadmin.arn]' in trust
        and 'identifiers = ["lambda.amazonaws.com"]' in trust
    )
    direct = "ssm:GetParameter" in a_user
    assume_then = trusted and "ssm:GetParameter" in a_role
    return PermissionAudit(
        frozenset(a_user), frozenset(a_role), trusted,
        True, bool(provider), direct, assume_then
    )


def synthetic_permission_check(audit: PermissionAudit, principal: str,
                               action: str, resource_tags: dict[str,str],
                               challenge_name: str = "local-mary") -> bool:
    """Simplified local IAM allow calculation only; never claims AWS parity."""
    if principal == "devopsadmin":
        return action in audit.user_actions
    if principal == "lambda-role":
        if not audit.user_trusted_by_lambda_role:
            return False
        if action == "ssm:GetParameter":
            return (action in audit.role_actions
                    and resource_tags.get("Challenge") == challenge_name)
        return action in audit.role_actions
    return False


def analyse(source: str) -> dict:
    result = audit_terraform(source)
    tag = {"Challenge": "local-mary"}
    if synthetic_permission_check(result, "devopsadmin", "ssm:GetParameter", tag):
        raise ValueError("Original admin unexpectedly has direct SSM access")
    if not synthetic_permission_check(result, "lambda-role", "ssm:GetParameter", tag):
        raise ValueError("Original trust/role chain not reproducible")
    return {
        "direct_user_access": result.direct_getparameter,
        "lambda_role_trusts_user": result.user_trusted_by_lambda_role,
        "assumed_role_access_with_matching_tag": result.assume_role_then_getparameter,
        "encrypted_ssm_parameter": True,
        "synthetic_only": True,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("terraform_source", type=Path)
    args = p.parse_args()
    r = analyse(args.terraform_source.read_text(encoding="utf-8"))
    print("Original IAM/Lambda policy chain recreated:", r)
    print("No live AWS account, real credentials, AssumeRole or GetParameter used.")


if __name__ == "__main__":
    main()
