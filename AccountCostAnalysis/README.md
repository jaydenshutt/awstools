# Account Cost Analysis

This tool analyzes an AWS account's costs using Cost Explorer and basic resource inventories, produces an HTML report with graphs, and gives recommendations to reduce costs.

Requirements
- Python 3.9+
- See `requirements.txt` to install dependencies: `pip install -r requirements.txt`

Usage
- Configure AWS credentials in your environment (AWS CLI, environment variables, or instance role).
- Run: `python analyze.py --output report.html`
- Use `--dry-run` to produce a sample report without calling AWS.

Profiles
- You can run the tool using an AWS CLI profile with the `--profile <name>` flag. This will use credentials and region from that profile.

Required permissions
- The tool requires AWS read-only permissions across several services to inventory resources and query costs. At minimum, the IAM principal should have permissions similar to:

	- `ce:GetCostAndUsage` (Cost Explorer)
	- `s3:ListBucket`, `s3:GetObject` (if reading CUR from S3)
	- `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeAddresses`, `ec2:DescribeSnapshots`
	- `rds:DescribeDBInstances`
	- `lambda:ListFunctions`
	- `elasticloadbalancing:DescribeLoadBalancers` / `elbv2:DescribeLoadBalancers`
	- `cloudfront:ListDistributions`
	- `dynamodb:ListTables`
	- `efs:DescribeFileSystems`
	- `autoscaling:DescribeAutoScalingGroups`
	- `ecr:DescribeRepositories`
	- `eks:ListClusters`
	- `sqs:ListQueues`
	- `ses:ListIdentities`

	Full Administrator access is not required; the above read-only permissions are sufficient. If you plan to read CUR files from S3, ensure the principal has access to the CUR bucket/prefix.

Notes
- This is a lightweight estimator. For complete cost breakdowns, enable Cost Explorer in the account and consider AWS CUR exports for deeper analysis.

Recommendations and savings estimates
-----------------------------------

This tool now includes a recommendations engine that inspects resource inventories, Cost Explorer aggregates, optional CUR data, and detected wasted resources to produce actionable suggestions. Each recommendation includes a conservative, back-of-the-envelope estimated monthly saving in USD where possible.

How estimates are calculated (high level):

- EC2: a conservative 15% of current monthly spend is used as an example estimate for rightsizing/reservations/savings plans. If EC2 is identified as the top service, an additional conservative 10% may be suggested for Spot/Savings Plan opportunities. These are heuristics and should be validated with a rightsizing analysis.
- RDS: a conservative 10% estimate for rightsizing or switching to serverless/reserved pricing where possible.
- S3: a conservative 5% estimate for data lifecycle and tiering improvements.

Caveats
- Estimates are heuristic, not exact. Actual savings depend on workload characteristics, commitment choices (RI/Savings Plans), data egress, and other account-specific factors.
- For per-resource accuracy, provide a CUR file (via `--cur-file` or `--cur-s3-bucket/--cur-prefix`) so the tool can attribute costs to specific resource IDs. CUR-backed recommendations will be more precise.
- Always validate recommendations in a staging or non-production environment before applying destructive actions (like terminating instances or deleting resources).

If you'd like, I can add more conservative/cautious modes, tuned estimates per-service (based on instance families, storage GB, Lambda invocations), or an exportable CSV of recommended actions for operational teams.

Author
-
This tool was authored by Jayden Shutt — https://www.linkedin.com/in/jaydenshutt/
