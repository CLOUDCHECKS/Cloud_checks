def check_granular_access_for_users(client):
    """
    Checks if users have granular permissions or wildcard permissions.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking Granular Access for Users -----")
    try:
        users_with_wide_permissions = []
        admin_users = []

        # Fetch all IAM users
        users = client.list_users()['Users']

        for user in users:
            user_name = user['UserName']
            attached_policies = client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            
            user_has_wide_permission = False
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_document = client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_version
                )['PolicyVersion']['Document']

                # Check if any statement contains wildcard '*' in Action
                statements = policy_document.get('Statement', [])
                if not isinstance(statements, list):
                    statements = [statements]

                for statement in statements:
                    if 'Action' in statement and ('*' in statement['Action'] or statement['Action'] == '*'):
                        user_has_wide_permission = True
                        break

            if user_has_wide_permission:
                users_with_wide_permissions.append(user_name)

            # Identify admin users (optional: based on role, group, or naming convention)
            if "Administrator" in user_name:  # Example: naming convention
                admin_users.append(user_name)

        # Prepare the result
        result = {
            "users_with_wide_permissions": users_with_wide_permissions,
            "admin_users": admin_users,
        }

        return result

    except Exception as e:
        return {"error": str(e)}
