from mcp.server.fastmcp import FastMCP
import boto3
import logging
import os
from github import Github
from dotenv import load_dotenv
from datetime import datetime, timedelta


load_dotenv()

logger = logging.getLogger('MCP Server')
logger.setLevel(logging.INFO)


access_token = os.environ.get("GITHUB_TOKEN")
github = Github(access_token)


mcp = FastMCP("Custom MCP Server", "0.1.0")


@mcp.tool()
def fetch_github_repo_info(repo: str) -> dict:
    """
    Fetches GitHub repository information (both public and private) using the provided repository name.
    :param repo: The name of the repository in the format 'owner/repo_name'.
    :return: A dictionary containing repository information such as name, description, owner, etc.
    """
    try:
        # verify the github has been initialized with the access token
        if not github or not access_token:
            print(f"access_token: {access_token}")
            print(f"github: {github}")
            raise ValueError("GitHub client is not initialized with a valid access token.")
        github_repo = github.get_repo(repo)
        return {
            "name": github_repo.name,
            "description": github_repo.description,
            "owner": github_repo.owner.login,
            "owner_url": github_repo.owner.html_url,
            "created_at": github_repo.created_at,
            "updated_at": github_repo.updated_at,
            "pushed_at": github_repo.pushed_at,
            "clone_url": github_repo.clone_url,
            "ssh_url": github_repo.ssh_url,
            "homepage": github_repo.homepage,
            "size": github_repo.size,
            "watchers": github_repo.watchers_count,
            "default_branch": github_repo.default_branch,
            "open_issues": github_repo.open_issues,
            "subscribers_count": github_repo.subscribers_count,
            "language": github_repo.language,
            "has_issues": github_repo.has_issues,
            "url": github_repo.html_url,
            "stars": github_repo.stargazers_count,
            "forks": github_repo.forks_count,
            "issues": github_repo.open_issues_count,
            "language": github_repo.language,
        }
    except Exception as e:
        print(f"Error fetching repository info: {e}")
        return None

@mcp.tool()
def fetch_aws_ec2_instances(region_name: str = "us-east-1") -> None:
    """
    Fetches and describes all EC2 instances in the specified AWS region.
    :param region_name: The name of the AWS region (e.g., 'us-east-1') default is 'us-east-1'.
    :return: A list of EC2 instances in the specified region.
    """
    # Initialize a session using Amazon EC2
    session = boto3.Session(region_name=region_name)

    # Initialize EC2 resource
    ec2_client = session.client('ec2')

    response = ec2_client.describe_instances(
        Filters=[{
            'Name': 'instance-state-name',
            'Values': ['pending', 'running', 'shutting-down', 'terminated', 'stopping', 'stopped']
        }]
    )

    # Fetch and return the instances from the response
    instances = []
    for reservation in response['Reservations']:
        instances.extend(reservation['Instances'])
    
    return instances

@mcp.tool()
def describe_ec2_instances(region_name: str = "us-east-1") -> None:
    """
    Fetches and describes all EC2 instances in the specified AWS region.
    :param region_name: The name of the AWS region (e.g., 'us-east-1') default is 'us-east-1'.
    :return: A list of EC2 instances in the specified region.
    """
    # Initialize a session using Amazon EC2
    session = boto3.Session(region_name=region_name)

    # Initialize EC2 client
    ec2_client = session.client('ec2')

    # Fetch all EC2 instances
    return ec2_client.describe_instances()


@mcp.tool()
def describe_ec2_instance_status(instance_ids: list, region_name: str = "us-east-1") -> None:
    """
    Fetches and describes the status of specified EC2 instances in the specified AWS region.
    :param instance_ids: A list of EC2 instance IDs to describe.
    :param region_name: The name of the AWS region (e.g., 'us-east-1') default is 'us-east-1'.
    :return: A list of EC2 instance statuses in the specified region.
    """
    # Initialize a session using Amazon EC2
    session = boto3.Session(region_name=region_name)

    # Initialize EC2 client
    ec2_client = session.client('ec2')

    # Fetch the status of specified EC2 instances
    return ec2_client.describe_instance_status(InstanceIds=instance_ids)


@mcp.tool()
def get_ec2_metrics(instance_id, start_time, end_time, period=300):
    """
    Retrieve EC2 monitoring metrics (CPUUtilization, NetworkIn, NetworkOut, etc.) for a given instance.
    
    Parameters:
    - instance_id: EC2 instance ID (str)
    - start_time: Start time for the metrics (datetime)
    - end_time: End time for the metrics (datetime)
    - period: Granularity of the metrics (in seconds, default is 300)
    
    Returns:
    - metrics: A dictionary of metrics data (e.g., CPU, Network, Disk, etc.)
    """
    cloudwatch = boto3.client('cloudwatch')

    # List of metrics to retrieve (you can add more metrics as needed)
    metric_names = [
        'CPUUtilization',
        'NetworkIn',
        'NetworkOut',
        'DiskReadOps',
        'DiskWriteOps',
        'DiskReadBytes',
        'DiskWriteBytes'
    ]
    
    metrics_data = {}

    for metric_name in metric_names:
        # Get metric data for each metric
        response = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': f'metric_{metric_name}',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/EC2',
                            'MetricName': metric_name,
                            'Dimensions': [
                                {
                                    'Name': 'InstanceId',
                                    'Value': instance_id
                                }
                            ]
                        },
                        'Period': period,
                        'Stat': 'Average',  # You can also use 'Sum', 'Maximum', etc.
                    },
                    'ReturnData': True
                }
            ],
            StartTime=start_time,
            EndTime=end_time
        )
        
        # Store the metric data in the dictionary
        if 'MetricDataResults' in response:
            metrics_data[metric_name] = response['MetricDataResults'][0].get('Values', [])
    
    return metrics_data

@mcp.tool()
def start_ec2_instance(instance_id: str, region_name: str = "us-east-1") -> None:
    """
    Starts an EC2 instance in the specified AWS region.
    :param instance_id: The ID of the EC2 instance to start.
    :param region_name: The name of the AWS region (e.g., 'us-east-1') default is 'us-east-1'.
    :return: None
    """
    # Initialize a session using Amazon EC2
    session = boto3.Session(region_name=region_name)

    # Initialize EC2 client
    ec2_client = session.client('ec2')

    # Start the specified EC2 instance
    ec2_client.start_instances(InstanceIds=[instance_id])
    logger.info(f"Started EC2 instance: {instance_id} in region: {region_name}")


@mcp.tool()
def shut_down_ec2_instance(instance_id: str, region_name: str = "us-east-1") -> None:
    """
    Shuts down an EC2 instance in the specified AWS region.
    :param instance_id: The ID of the EC2 instance to shut down.
    :param region_name: The name of the AWS region (e.g., 'us-east-1') default is 'us-east-1'.
    :return: None
    """
    # Initialize a session using Amazon EC2
    session = boto3.Session(region_name=region_name)

    # Initialize EC2 client
    ec2_client = session.client('ec2')

    # Stop the specified EC2 instance
    ec2_client.stop_instances(InstanceIds=[instance_id])
    logger.info(f"Shut down EC2 instance: {instance_id} in region: {region_name}")