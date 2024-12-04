def check_mfa_for_users(client):
    """
    Checks if MFA is enabled for all IAM users.
    Returns a formatted dictionary with the findings.
    """
    print("----- Checking MFA Enforced for All Users -----")

    users_without_mfa = []

    try:
        # List all IAM users
        users = client.list_users()['Users']
        for user in users:
            user_name = user['UserName']
            
            # List MFA devices for the user
            mfa_devices = client.list_mfa_devices(UserName=user_name)['MFADevices']
            
            if not mfa_devices:
                users_without_mfa.append(user_name)

        # Determine the summary based on findings
        if not users_without_mfa:
            summary = "(+) All users have MFA enabled."
        else:
            summary = "(-) Users without MFA enabled."

        # Prepare the result
        result = {
            "Topic": "Authentication & authorization for access",
            "Requirement": "Multifactor authentication",
            "Need to Achieve": "Need to check that, every user should have policy enforced to enable MFA.",
            "Function Used": "check_mfa_for_users",
            "Results": {
                "Summary": summary,
                "Users without MFA": users_without_mfa if users_without_mfa else "No users without MFA."
            }
        }

        return result

    except Exception as e:
        return {
            "Topic": "Authentication & authorization for access",
            "Requirement": "Multifactor authentication",
            "Need to Achieve": "Need to check that, every user should have policy enforced to enable MFA.",
            "Function Used": "check_mfa_for_users",
            "Results": {
                "Error": f"Error checking MFA for users: {str(e)}"
            }
        }
