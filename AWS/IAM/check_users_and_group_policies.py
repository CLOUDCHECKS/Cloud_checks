def check_users_and_group_policies(client):
    """
    Checks if all users belong to groups and all groups have policies.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking Users, Group Memberships, and Group Policies -----")
    try:
        all_users_in_groups = True
        all_groups_have_policies = True

        # Check if all users belong to at least one group
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            user_groups = client.list_groups_for_user(UserName=user_name)['Groups']
            if not user_groups:
                all_users_in_groups = False

        # Check if all groups have at least one policy (managed or inline)
        groups = client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            inline_policies = client.list_group_policies(GroupName=group_name)['PolicyNames']
            if not attached_policies and not inline_policies:
                all_groups_have_policies = False

        # Prepare the result as a dictionary
        result = {
            "all_users_in_groups": all_users_in_groups,
            "all_groups_have_policies": all_groups_have_policies,
        }

        return result

    except Exception as e:
        return {"error": str(e)}
