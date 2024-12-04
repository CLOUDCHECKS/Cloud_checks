def check_least_privilege_access(client):
    """
    Checks for users, roles, and groups with wildcard permissions (*).
    Returns a formatted string with the findings.
    """
    print("----- Checking Least Privilege Access -----")
    
    resources_with_wide_permissions = []
    users_without_appropriate_permissions = []
    roles_without_appropriate_permissions = []
    groups_without_appropriate_permissions = []

    try:
        # Check for wildcard permissions in IAM users
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            attached_policies = client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            for policy in attached_policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )['PolicyVersion']['Document']

                # Check for wildcard permissions
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for statement in statements:
                    if 'Action' in statement and ('*' in statement['Action'] or statement['Action'] == '*'):
                        resources_with_wide_permissions.append(f"User: {user_name}, Policy: {policy_name}")
                        users_without_appropriate_permissions.append(user_name)

        # Check for wildcard permissions in IAM roles
        roles = client.list_roles()['Roles']
        for role in roles:
            role_name = role['RoleName']
            attached_policies = client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached_policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )['PolicyVersion']['Document']

                # Check for wildcard permissions
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for statement in statements:
                    if 'Action' in statement and ('*' in statement['Action'] or statement['Action'] == '*'):
                        resources_with_wide_permissions.append(f"Role: {role_name}, Policy: {policy_name}")
                        roles_without_appropriate_permissions.append(role_name)

        # Check for wildcard permissions in IAM groups
        groups = client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            for policy in attached_policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )['PolicyVersion']['Document']

                # Check for wildcard permissions
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]
                for statement in statements:
                    if 'Action' in statement and ('*' in statement['Action'] or statement['Action'] == '*'):
                        resources_with_wide_permissions.append(f"Group: {group_name}, Policy: {policy_name}")
                        groups_without_appropriate_permissions.append(group_name)

        # Determine the summary based on findings
        if not resources_with_wide_permissions:
            summary = "(+) No policies with wildcard (*) permissions found."
        else:
            summary = "(-) Policies with wildcard (*) permissions found."

        # Prepare the result
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Correlation between physical and logical access",
            "Need to Achieve": "Need to check every resource having least privilege access.",
            "Function Used": "check_least_privilege_access",
            "Results": {
                "Summary": summary,
                "Users with Wildcard Permissions": users_without_appropriate_permissions if users_without_appropriate_permissions else "No users with wildcard permissions.",
                "Roles with Wildcard Permissions": roles_without_appropriate_permissions if roles_without_appropriate_permissions else "No roles with wildcard permissions.",
                "Groups with Wildcard Permissions": groups_without_appropriate_permissions if groups_without_appropriate_permissions else "No groups with wildcard permissions."
            }
        }

        return result

    except Exception as e:
        return {
            "4) Topic": "Governance procedures for access rights, identity & privileges",
            "    Requirement": "Correlation between physical and logical access",
            "    Need to Achieve": "Need to check every resource having least privilege access.",
            "    Function Used": "check_least_privilege_access",
            "    Results": {
                "Error": f"Error checking wildcard permissions: {str(e)}"
            }
        }
