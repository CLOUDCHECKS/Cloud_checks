def check_least_privilege_and_group_policies(client):
    """
    Checks if all users have least privilege access, belong to a group with policies,
    and whether all groups have policies.
    Returns a JSON-friendly dictionary with the findings.
    """
    print("----- Checking if all users have least privilege access and belong to a group with policies -----")
    
    least_privilege = True  # Flag to track if all users have least privilege
    all_users_in_groups = True
    all_groups_have_policies = True
    
    users_not_compliant = []
    groups_without_policies = []

    try:
        # Create IAM client
        iam_client = client
        
        # Get all users
        users = iam_client.list_users()['Users']

        # Check each user for compliance with least privilege
        for user in users:
            user_name = user['UserName']
            user_compliance = {"user": user_name, "reasons": []}

            # Check if the user belongs to at least one group
            user_groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
            if not user_groups:
                all_users_in_groups = False
                user_compliance["reasons"].append("User does not belong to any group.")
            
            # Check attached policies for wildcard permissions
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_document = iam_client.get_policy(PolicyArn=policy_arn)['Policy']
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn, 
                    VersionId=policy_document['DefaultVersionId']
                )['PolicyVersion']

                # Check if the policy contains any wildcard permissions
                statements = policy_version['Document'].get('Statement', [])
                if isinstance(statements, dict):  # Ensure it's a list for iteration
                    statements = [statements]
                for statement in statements:
                    if '*' in statement.get('Action', ''):
                        least_privilege = False
                        user_compliance["reasons"].append("Policy contains wildcard permissions.")

            # Check inline policies for wildcard actions
            inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']
            for inline_policy in inline_policies:
                policy_document = iam_client.get_user_policy(UserName=user_name, PolicyName=inline_policy)['PolicyDocument']
                statements = policy_document.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                for statement in statements:
                    if '*' in statement.get('Action', ''):
                        least_privilege = False
                        user_compliance["reasons"].append("Inline policy contains wildcard permissions.")

            if user_compliance["reasons"]:
                users_not_compliant.append(user_compliance)
        
        # Check if all groups have at least one policy
        groups = iam_client.list_groups()['Groups']
        for group in groups:
            group_name = group['GroupName']
            attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
            inline_policies = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
            if not attached_policies and not inline_policies:
                all_groups_have_policies = False
                groups_without_policies.append(group_name)

        # Prepare the result
        result = {
            "Topic": "Segregation of duties",
            "Requirement": "Segregation of duties",
            "Need to Achieve": "Need to check that all the users have least privilege access. And IAM Groups are created and policies are attached to groups.",
            "Function Used": "check_least_privilege_and_group_policies",
            "Results": {
                "Summary": "",
                "Users Not Compliant": users_not_compliant,
                "Groups Without Policies": groups_without_policies
            }
        }

        # Create the summary based on flags and issues
        if least_privilege and all_users_in_groups and all_groups_have_policies:
            result["Results"]["Summary"] = "(+) All users have least privilege access, belong to a group, and all groups have policies."
        elif least_privilege and all_users_in_groups and not all_groups_have_policies:
            result["Results"]["Summary"] = "(+) All users have least privilege access, belong to a group, but not all groups have policies."
        elif least_privilege and not all_users_in_groups and not all_groups_have_policies:
            result["Results"]["Summary"] = "(+) All users have least privilege access, but not all belong to a group and not all groups have policies."
        elif not least_privilege and not all_users_in_groups and not all_groups_have_policies:
            result["Results"]["Summary"] = "(-) Not all users have least privilege access, not all belong to a group, and not all groups have policies."
        elif not least_privilege and all_users_in_groups and not all_groups_have_policies:
            result["Results"]["Summary"] = "(-) Not all users have least privilege access, but all belong to a group, and not all groups have policies."
        elif not least_privilege and not all_users_in_groups and all_groups_have_policies:
            result["Results"]["Summary"] = "(-) Not all users have least privilege access, not all belong to a group, but all groups have policies."
        elif not least_privilege and all_users_in_groups and all_groups_have_policies:
            result["Results"]["Summary"] = "(-) Not all users have least privilege access, but all belong to a group and all groups have policies."
        else:
            result["Results"]["Summary"] = "(-) Unexpected result in checking least privilege and group policies."

        return result

    except Exception as e:
        return {
            "summary": f"Error during check: {str(e)}",
            "users_not_compliant": [],
            "groups_without_policies": []
        }
