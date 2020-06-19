#==================================================================================================
# Function: CheckAndCorrectObjectACL
# Purpose:  Evaluates whether the ACL on the S3 object needs to be changed
#==================================================================================================
from __future__ import print_function
import json
import boto3, time
import os
import datetime
from time import gmtime, strftime

s3                 = boto3.client('s3')
bucket_of_interest = os.environ["S3_BUCKET"]
sns_topic_arn      = os.environ["TOPIC_ARN"]
date_fmt           = strftime("%d_%m_%Y_%H:%M:%S", gmtime())              #get to the current date
# For a PutObjectAcl API Event, gets the bucket and key name from the event
# If the object is not private, then it makes the object private by making a PutObjectAcl call.
def lambda_handler(event, context):
    # Get bucket name from the event
    bucket = event['detail']['requestParameters']['bucketName']
    if (bucket != bucket_of_interest):
        print("Doing nothing for bucket = " + bucket)
        return
    # Get key name from the event
    key = event['detail']['requestParameters']['key']
    # If object is not private then make it private
    if not (is_private(bucket, key)):
        print("Object with key=" + key + " in bucket=" + bucket + " is not private!")
        make_private(bucket, key)
    else:
        print("Object with key=" + key + " in bucket=" + bucket + " is already private.")
# Checks an object with given bucket and key is private
def is_private(bucket, key):
    # Get the object ACL from S3
    acl = s3.get_object_acl(Bucket=bucket, Key=key)
    # Private object should have only one grant which is the owner of the object
    if (len(acl['Grants']) > 1):
        return False
    # If canonical owner and grantee ids do no match, then conclude that the object is not private
    owner_id   = acl['Owner']['ID']
    grantee_id = acl['Grants'][0]['Grantee']['ID']
    if (owner_id != grantee_id):
        return False
    return True
# Makes an object with given bucket and key private by calling the PutObjectAcl API.
def make_private(bucket, key):
    s3.put_object_acl(Bucket=bucket, Key=key, ACL="private")
    print("Object with key=" + key + " in bucket=" + bucket + " is marked as private.")
    if (send_sns(bucket, key)):
        print("SNS sent to notify about the change")
# Section that sends notification to SNS topic on object made private
def send_sns(bucket, key):
    sns_client       = boto3.client('sns')
    subject          = 'AWS S3 Object ACL Change in bucket - ' + bucket + ' - ' + date_fmt
    message_body     = '\n\n Object with key= ' + key + '  in bucket=' + bucket + '  is marked as private. \n'
    resp_sns         = sns_client.publish(TopicArn=sns_topic_arn, Message=message_body, Subject=subject)
    if resp_sns is not None:
        return True
    else:
        return False

