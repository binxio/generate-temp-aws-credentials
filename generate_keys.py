import urllib, json, requests, sys, boto3

if len(sys.argv[1:]) != 3:
    print 'use: python generate_keys.py session_name role_arn output_format'
    exit(1)
else:
    session_name = sys.argv[1]
    role_arn = sys.argv[2]
    output = sys.argv[3]

sts_connection = boto3.client('sts')

assumed_role_object = sts_connection.assume_role(
    RoleArn=role_arn,
    RoleSessionName=session_name
)

json_string_with_temp_credentials = '{'
json_string_with_temp_credentials += '"sessionId":"' + assumed_role_object['Credentials']['AccessKeyId'] + '",'
json_string_with_temp_credentials += '"sessionKey":"' + assumed_role_object['Credentials']['SecretAccessKey'] + '",'
json_string_with_temp_credentials += '"sessionToken":"' + assumed_role_object['Credentials']['SessionToken'] + '"'
json_string_with_temp_credentials += '}'

request_parameters = "?Action=getSigninToken"
request_parameters += "&SessionDuration=43200"
request_parameters += "&Session=" + urllib.quote_plus(json_string_with_temp_credentials)
request_url = "https://signin.aws.amazon.com/federation" + request_parameters
r = requests.get(request_url)
signin_token = json.loads(r.text)

request_parameters = "?Action=login" 
request_parameters += "&Issuer=Instruqt" 
request_parameters += "&Destination=" + urllib.quote_plus("https://console.aws.amazon.com/")
request_parameters += "&SigninToken=" + signin_token["SigninToken"]
request_url = "https://signin.aws.amazon.com/federation" + request_parameters

parsed = {}

parsed['access_key'] = assumed_role_object['Credentials']['AccessKeyId']
parsed['secret_key'] = assumed_role_object['Credentials']['SecretAccessKey']
parsed['session_token'] = assumed_role_object['Credentials']['SessionToken']
parsed['console_access'] = request_url

if output == 'credentials':
    print "[tmpinstruqt]"
    print "aws_access_key_id = " + assumed_role_object['Credentials']['AccessKeyId']
    print "aws_secret_access_key = " + assumed_role_object['Credentials']['SecretAccessKey']
    print "aws_session_token = " + assumed_role_object['Credentials']['SessionToken']

elif output == "link":
    print request_url

else: 
    print json.dumps(parsed, indent=4)