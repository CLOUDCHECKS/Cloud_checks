def check_users_and_group_policies(client):
    """
    Checks if all users belong to at least one group and if all groups have associated policies.
    Returns a dictionary formatted for the PDF.
    """
    print("----- Checking IAM users are added to a group and those groups have policies attached -----")
    
    try:
        # Initialize result variables
        users_without_groups = []
        groups_without_policies = []
        all_users_in_groups = True
        all_groups_have_policies = True

        # List all users and check if they belong to at least one group
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            user_groups = client.list_groups_for_user(UserName=user_name)['Groups']
            if not user_groups:
                users_without_groups.append(user_name)
                all_users_in_groups = False

        # List all groups and check if each group has at least one policy (managed or inline)
        groups = client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            inline_policies = client.list_group_policies(GroupName=group_name)['PolicyNames']
            if not attached_policies and not inline_policies:
                groups_without_policies.append(group_name)
                all_groups_have_policies = False

        # Determine the summary based on findings
        if not users_without_groups and not groups_without_policies:
            summary = "(+) All users belong to a group, and all groups have policies."
        elif not users_without_groups:
            summary = "(-) All users belong to a group, but not all groups have policies."
        elif not groups_without_policies:
            summary = "(-) Not all users belong to a group, but all groups have policies."
        else:
            summary = "(-) Not all users belong to a group, and not all groups have policies."

        # Prepare the result
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Mapping and grouping of business roles with IT roles",
            "Need to Achieve": "Need to check that all users belong to a group, and policies are assigned to the group.",
            "Function Used": "check_users_and_group_policies",
            "Results": {
                "Summary": summary,
                "Users Without Groups": users_without_groups if users_without_groups else "All users belong to a group.",
                "Groups Without Policies": groups_without_policies if groups_without_policies else "All groups have policies."
            }
        }
        return result

    except Exception as e:
        return {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Mapping and grouping of business roles with IT roles",
            "Need to Achieve": "Need to check that all users belong to a group, and policies are assigned to the group.",
            "Function Used": "check_users_and_group_policies",
            "Results": {
                "Error": f"Error during user and group policy check: {str(e)}"
            }
        }

