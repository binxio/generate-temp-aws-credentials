import boto3
client = boto3.resource(
    's3',
    aws_access_key_id='ASIAL34H2K3423KL4JLKJLKJ',
    aws_secret_access_key='e0hvLM234LKJ23KDAdsf23DFAXiBrNu8Ht',
    aws_session_token='F4adsJL2sdafK3J42K3LJ4erg2K3J4....',
)
for bucket in client.buckets.all():
    print(bucket.name)