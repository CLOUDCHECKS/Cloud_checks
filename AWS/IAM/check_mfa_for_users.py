def check_mfa_for_users(client):
    """
    Checks if MFA is enforced for all IAM users.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking MFA Enforced for All Users -----")
    try:
        mfa_enabled_for_all = True
        users = client.list_users()['Users']

        # Check if each user has at least one MFA device
        for user in users:
            user_name = user['UserName']
            mfa_devices = client.list_mfa_devices(UserName=user_name)['MFADevices']
            if not mfa_devices:
                mfa_enabled_for_all = False

        # Prepare the result as a dictionary
        result = {
            "mfa_enabled_for_all": mfa_enabled_for_all,
        }

        return result

    except Exception as e:
        return {"error": str(e)}
