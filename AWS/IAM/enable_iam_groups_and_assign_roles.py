def enable_iam_groups_and_assign_roles(client):
    """
    Enables IAM Groups and assigns roles to the groups.
    Returns a dictionary formatted for the PDF.
    """
    print("----- Enabling IAM Groups and Assigning Roles in Groups -----")
    try:
        all_users_in_groups = True
        all_groups_have_policies = True
        users_without_groups = []
        groups_without_policies = []

        # Check if all users belong to at least one group
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            user_groups = client.list_groups_for_user(UserName=user_name)['Groups']
            if not user_groups:
                all_users_in_groups = False
                users_without_groups.append(user_name)

        # Check if all groups have at least one policy (managed or inline)
        groups = client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            inline_policies = client.list_group_policies(GroupName=group_name)['PolicyNames']
            if not attached_policies and not inline_policies:
                all_groups_have_policies = False
                groups_without_policies.append(group_name)

        # Determine the summary based on findings
        if all_users_in_groups and all_groups_have_policies:
            summary = "(+) All users are in groups, and all groups have policies."
        elif all_users_in_groups:
            summary = "(-) All users are in groups, but not all groups have policies."
        elif all_groups_have_policies:
            summary = "(-) Not all users are in groups, but all groups have policies."
        else:
            summary = "(-) Not all users are in groups, and not all groups have policies."

        # Prepare the result
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Strict enforcement of access policies across infrastructure components",
            "Need to Achieve": "Enabling IAM Group and assigning roles in the Group.",
            "Function Used": "enable_iam_groups_and_assign_roles",
            "Results": {
                "Summary": summary,
                "Users Without Groups": users_without_groups if users_without_groups else "All users are in groups.",
                "Groups Without Policies": groups_without_policies if groups_without_policies else "All groups have policies."
            }
        }

        return result

    except Exception as e:
        return {
            "3) Topic": "Governance procedures for access rights, identity & privileges",
            "    Requirement": "Strict enforcement of access policies across infrastructure components",
            "    Need to Achieve": "Enabling IAM Group and assigning roles in the Group.",
            "    Function Used": "enable_iam_groups_and_assign_roles",
            "    Results": {
                "Error": f"Error enabling IAM Groups and assigning roles: {str(e)}"
            }
        }
