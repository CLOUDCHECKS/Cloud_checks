def check_least_privilege_access(client):
    """
    Checks if any users, roles, or groups have wildcard permissions.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking Least Privilege Access -----")
    try:
        resources_with_wide_permissions = []

        # Check all IAM users
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            attached_policies = client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            for policy in attached_policies:
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
                        resources_with_wide_permissions.append({"type": "User", "name": user_name})

        # Check all IAM roles
        roles = client.list_roles()['Roles']
        for role in roles:
            role_name = role['RoleName']
            attached_policies = client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached_policies:
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
                        resources_with_wide_permissions.append({"type": "Role", "name": role_name})

        # Check all IAM groups
        groups = client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            for policy in attached_policies:
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
                        resources_with_wide_permissions.append({"type": "Group", "name": group_name})

        return {"resources_with_wide_permissions": resources_with_wide_permissions}

    except Exception as e:
        return {"error": str(e)}
