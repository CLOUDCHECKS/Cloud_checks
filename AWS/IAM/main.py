import argparse
import boto3
from check_users_and_group_policies import check_users_and_group_policies
from check_analyzer_status import check_analyzer_status
from enable_iam_groups_and_assign_roles import enable_iam_groups_and_assign_roles
from check_least_privilege_access import check_least_privilege_access
from check_granular_access_for_users import check_granular_access_for_users
from check_root_and_access_analyzer import check_root_and_access_analyzer
from check_mfa_for_users import check_mfa_for_users
from check_aws_ad_connector import check_aws_ad_connector
from check_password_policy import check_password_policy
from check_password_policy_for_users import check_password_policy_for_users
from check_cloudtrail_logs_enabled import check_cloudtrail_logs_enabled
from check_least_privilege_and_group_policies import check_least_privilege_and_group_policies
from fpdf import FPDF  # Assuming PDFMake is not directly used in Python, FPDF is commonly used.

def generate_pdf(results):
    """
    Generates a PDF report from the results.

    Args:
        results (dict): A dictionary containing the results of the checks.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Add title
    pdf.cell(200, 10, txt="AWS Security Check Report", ln=True, align="C")
    pdf.ln(10)

    # Add results to the PDF
    for key, value in results.items():
        if isinstance(value, list):  # If it's a list, format it
            pdf.cell(200, 10, txt=f"{key}:", ln=True)
            for item in value:
                pdf.cell(200, 10, txt=f" - {item}", ln=True)
            pdf.ln(5)
        elif isinstance(value, dict):
            for sub_key, sub_value in value.items():
                pdf.cell(200, 10, txt=f"{sub_key}: {sub_value}", ln=True)
            pdf.ln(5)
        else:
            pdf.cell(200, 10, txt=f"{key}: {value}", ln=True)
            pdf.ln(5)

    # Save PDF to file
    pdf.output("AWS_Security_Check_Report.pdf")
    print("PDF report generated successfully.")


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="AWS Security Check Script")
    parser.add_argument("-p", "--profile", help="AWS profile to use", required=True)
    parser.add_argument("-m", "--mode", help="Mode (check_users_and_group_policies, check_analyzer_status, "
                                              "enable_iam_groups_and_assign_roles, check_least_privilege_access, "
                                              "check_granular_access_for_users, check_mfa_for_users, check_aws_ad_connector, "
                                              "check_password_policy, check_password_policy_for_users, "
                                              "check_cloudtrail_logs_enabled, check_least_privilege_and_group_policies, all)",
                        required=True)
    args = parser.parse_args()

    profile = args.profile
    mode = args.mode

    # Initialize AWS session and client
    session = boto3.Session(profile_name=profile)
    client = session.client('iam')

    # Initialize result dictionary
    results = {}

    # Mode-specific checks
    if mode == 'check_users_and_group_policies' or mode == 'all':
        results["check_users_and_group_policies"] = check_users_and_group_policies(client)
    if mode == 'check_analyzer_status' or mode == 'all':
        results["check_analyzer_status"] = check_analyzer_status(client)
    if mode == 'enable_iam_groups_and_assign_roles' or mode == 'all':
        results["enable_iam_groups_and_assign_roles"] = enable_iam_groups_and_assign_roles(client)
    if mode == 'check_least_privilege_access' or mode == 'all':
        results["check_least_privilege_access"] = check_least_privilege_access(client)
    if mode == 'check_granular_access_for_users' or mode == 'all':
        results["check_granular_access_for_users"] = check_granular_access_for_users(client)
    if mode == 'check_root_and_access_analyzer' or mode == 'all':
        results["check_root_and_access_analyzer"] = check_root_and_access_analyzer(client)
    if mode == 'check_mfa_for_users' or mode == 'all':
        results["check_mfa_for_users"] = check_mfa_for_users(client)
    if mode == 'check_aws_ad_connector' or mode == 'all':
        results["check_aws_ad_connector"] = check_aws_ad_connector(client)
    if mode == 'check_password_policy' or mode == 'all':
        results["check_password_policy"] = check_password_policy(client)
    if mode == 'check_password_policy_for_users' or mode == 'all':
        results["check_password_policy_for_users"] = check_password_policy_for_users(client)
    if mode == 'check_cloudtrail_logs_enabled' or mode == 'all':
        results["check_cloudtrail_logs_enabled"] = check_cloudtrail_logs_enabled(client)
    if mode == 'check_least_privilege_and_group_policies' or mode == 'all':
        results["check_least_privilege_and_group_policies"] = check_least_privilege_and_group_policies(client)

    # Generate PDF with results
    generate_pdf(results)


if __name__ == "__main__":
    main()
