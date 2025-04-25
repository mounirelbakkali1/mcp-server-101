from dotenv import load_dotenv
import logging
from tools.GithubAccountExplorer import fetch_github_repo_info
from tools.AWSCloudAccountExplorer import fetch_aws_ec2_instances, describe_ec2_instances


logging.basicConfig()  # Add logging level here if you plan on using logging.info() instead of my_logger as below.

logger = logging.getLogger(__name__)
logger .setLevel(logging.INFO)
load_dotenv()


def main():
    # Testing MCP server custom tools
    repo_info = fetch_github_repo_info("mounirelbakkali1/pharma-saas")
    ec2_instances = fetch_aws_ec2_instances()
    ec2_instances_described = describe_ec2_instances()
    logger.info(f"ec2_instances: {ec2_instances}")
    logger.info("__________________________________________________________________________________")
    logger.info(f"ec2_instances_described: {ec2_instances_described}")
    logger.info("__________________________________________________________________________________")
    logger.info(f"repo_info: {repo_info}")
    logger.info("__________________________________________________________________________________")

if __name__ == "__main__":
    main()
