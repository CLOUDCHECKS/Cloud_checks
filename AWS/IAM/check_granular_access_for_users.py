def check_granular_access_for_users(client):
    """
    Checks for users with wildcard permissions (*) and identifies admin users.
    Returns a formatted string with the findings.
    """
    print("----- Checking Granular Access for Users -----")
    
    users_with_wide_permissions = []
    admin_users = []
    users_with_granular_permissions = []

    try:
        # Fetch all IAM users
        users = client.list_users()['Users']

        for user in users:
            user_name = user['UserName']
            attached_policies = client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']

            user_has_wide_permission = False
            for policy in attached_policies:
                policy_name = policy['PolicyName']
                policy_arn = policy['PolicyArn']

                # Retrieve the policy document
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
                    break
            # Identify users with granular permissions (users without wildcard permissions)
            if not user_has_wide_permission:
                users_with_granular_permissions.append(user_name)

            # Identify admin users (based on naming convention or custom criteria)
            if "Administrator" in user_name:  # Example: naming convention
                admin_users.append(user_name)

        # Determine the summary based on findings
        if not users_with_wide_permissions:
            summary = "(+) All users have granular permissions."
        else:
            summary = "(-) Users with wildcard permissions found."

        # Prepare the result
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Role-based access control, Authorization as per security access matrix",
            "Need to Achieve": "User having granular access attached to them. Limited resources-level admin user which need to be listed.",
            "Function Used": "check_granular_access_for_users",
            "Results": {
                "Summary": summary,
                "Users with Granular Access": users_with_granular_permissions if users_with_granular_permissions else "No users with granular access.",
                "Users with Wildcard Permissions": users_with_wide_permissions if users_with_wide_permissions else "No users with wildcard permissions.",
                "Admin Users": admin_users if admin_users else "No admin users found."
            }
        }

        return result

    except Exception as e:
        return {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Role-based access control, Authorization as per security access matrix",
            "Need to Achieve": "User having granular access attached to them. Limited resources-level admin user which need to be listed.",
            "Function Used": "check_granular_access_for_users",
            "Results": {
                "Error": f"Error checking granular access for users: {str(e)}"
            }
        }
