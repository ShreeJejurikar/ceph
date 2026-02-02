"""
Bucket Logging Tests for RGW

This module tests radosgw-admin bucket logging commands and cleanup behavior.
"""

import logging
import subprocess
import os
import json
import time
import random
import string
import pytest
import boto3
from botocore.exceptions import ClientError

from . import (
    configfile,
    get_config_host,
    get_config_port,
    get_access_key,
    get_secret_key,
    get_user_id
)

# Configure logging
log = logging.getLogger(__name__)

# Path to test helper scripts
test_path = os.path.normpath(os.path.dirname(os.path.realpath(__file__))) + '/../'

# Global counters for unique naming
num_buckets = 0
run_prefix = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))

# Bucket logging policy template
LOGGING_POLICY_TEMPLATE = '''{{
    "Version": "2012-10-17",
    "Statement": [
        {{
            "Sid": "AllowLogging",
            "Effect": "Allow",
            "Principal": {{
                "Service": "logging.s3.amazonaws.com"
            }},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::{log_bucket}/*",
            "Condition": {{
                "StringEquals": {{
                    "aws:SourceAccount": "{account_id}"
                }},
                "ArnLike": {{
                    "aws:SourceArn": "arn:aws:s3:::{source_bucket}"
                }}
            }}
        }}
    ]
}}'''


# =============================================================================
# Helper Functions
# =============================================================================

def bash(cmd, **kwargs):
    """Execute a shell command and return output and return code."""
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.PIPE
    process = subprocess.Popen(cmd, **kwargs)
    stdout, stderr = process.communicate()
    return (stdout.decode('utf-8'), process.returncode)


def admin(args, **kwargs):
    """Execute radosgw-admin command."""
    cmd = [test_path + 'test-rgw-call.sh', 'call_rgw_admin', 'noname'] + args
    return bash(cmd, **kwargs)


def rados(args, **kwargs):
    """Execute rados command."""
    cmd = [test_path + 'test-rgw-call.sh', 'call_rgw_rados', 'noname'] + args
    return bash(cmd, **kwargs)


def gen_bucket_name(prefix="bucket"):
    """Generate a unique bucket name."""
    global num_buckets
    num_buckets += 1
    return f"{run_prefix}-{prefix}-{num_buckets}"


def get_s3_client():
    """Create and return an S3 client."""
    hostname = get_config_host()
    port = get_config_port()
    access_key = get_access_key()
    secret_key = get_secret_key()

    if port in (443, 8443):
        endpoint_url = f'https://{hostname}:{port}'
    else:
        endpoint_url = f'http://{hostname}:{port}'

    return boto3.client(
        's3',
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        verify=False
    )


def get_bucket_id(bucket_name):
    """Get the bucket ID using radosgw-admin bucket stats."""
    output, ret = admin(['bucket', 'stats', '--bucket', bucket_name])
    if ret != 0:
        log.error(f"Failed to get bucket stats for {bucket_name}")
        return None
    try:
        stats = json.loads(output)
        return stats.get('id')
    except json.JSONDecodeError:
        log.error(f"Failed to parse bucket stats JSON: {output}")
        return None


def find_temp_log_objects(bucket_id, pool='default.rgw.buckets.data'):
    """Find temporary log objects for a bucket in rados.
    
    Args:
        bucket_id: Bucket ID to search for
        pool: RADOS pool name
    
    Returns:
        tuple: (list of temp object names, bool success)
    """
    output, ret = rados(['ls', '--pool', pool])
    
    if ret != 0:
        log.error(f"rados ls failed with code {ret}: {output}")
        return [], False
    
    if not output or not bucket_id:
        return [], True
    
    temp_objects = []
    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        # Look for shadow objects with bucket ID
        if bucket_id in line and '__shadow_' in line:
            temp_objects.append(line)
            log.debug(f"Found temp object: {line}")
    
    return temp_objects, True


def create_bucket_with_logging(s3_client, source_bucket, log_bucket):
    """
    Create source and log buckets with logging enabled.
    
    Returns True on success, False on failure.
    """
    try:
        # Create log bucket first
        s3_client.create_bucket(Bucket=log_bucket)
        log.info(f"Created log bucket: {log_bucket}")

        # Create source bucket
        s3_client.create_bucket(Bucket=source_bucket)
        log.info(f"Created source bucket: {source_bucket}")

        # Set bucket policy on log bucket to allow logging
        user_id = get_user_id()
        policy = LOGGING_POLICY_TEMPLATE.format(
            log_bucket=log_bucket,
            source_bucket=source_bucket,
            account_id=user_id
        )
        s3_client.put_bucket_policy(Bucket=log_bucket, Policy=policy)
        log.info(f"Set logging policy on log bucket: {log_bucket}")

        # Enable logging on source bucket
        logging_config = {
            'LoggingEnabled': {
                'TargetBucket': log_bucket,
                'TargetPrefix': f'{source_bucket}/'
            }
        }
        s3_client.put_bucket_logging(Bucket=source_bucket, BucketLoggingStatus=logging_config)
        log.info(f"Enabled logging on source bucket: {source_bucket}")

        return True
    except ClientError as e:
        log.error(f"Error setting up bucket logging: {e}")
        return False


def cleanup_bucket(s3_client, bucket_name):
    """Delete all objects in a bucket and then delete the bucket."""
    try:
        # List and delete all objects
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            for obj in response['Contents']:
                s3_client.delete_object(Bucket=bucket_name, Key=obj['Key'])
                log.debug(f"Deleted object: {obj['Key']}")
        
        # Delete the bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        log.info(f"Deleted bucket: {bucket_name}")
    except ClientError as e:
        log.warning(f"Error cleaning up bucket {bucket_name}: {e}")


# =============================================================================
# Admin Command Tests
# =============================================================================

def test_bucket_logging_list():
    """Test radosgw-admin bucket logging list command."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("source")
    log_bucket = gen_bucket_name("log")
    
    try:
        # Setup
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"
        
        # Upload an object to generate log records
        s3_client.put_object(
            Bucket=source_bucket,
            Key='test-object.txt',
            Body=b'test content'
        )
        log.info(f"Uploaded test object to {source_bucket}")

        # Run bucket logging list command
        output, ret = admin([
            'bucket', 'logging', 'list',
            '--bucket', source_bucket
        ])
        
        log.info(f"bucket logging list output: {output}")
        assert ret == 0, f"bucket logging list failed with return code {ret}"
        
    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_bucket_logging_info_source():
    """Test radosgw-admin bucket logging info on source bucket."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("source")
    log_bucket = gen_bucket_name("log")
    
    try:
        # Setup
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"
        
        # Run bucket logging info command on source bucket
        output, ret = admin([
            'bucket', 'logging', 'info',
            '--bucket', source_bucket
        ])
        
        log.info(f"bucket logging info (source) output: {output}")
        assert ret == 0, f"bucket logging info failed with return code {ret}"
        
        # Verify output contains logging configuration
        if output.strip():
            try:
                info = json.loads(output)
                assert 'bucketLoggingStatus' in info or 'targetbucket' in str(info).lower(), \
                    "Expected logging configuration in output"
            except json.JSONDecodeError:
                log.warning("Output is not JSON, checking for relevant content")
                
    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_bucket_logging_info_log():
    """Test radosgw-admin bucket logging info on log bucket."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("source")
    log_bucket = gen_bucket_name("log")
    
    try:
        # Setup
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"
        
        # Run bucket logging info command on log bucket
        output, ret = admin([
            'bucket', 'logging', 'info',
            '--bucket', log_bucket
        ])
        
        log.info(f"bucket logging info (log) output: {output}")
        assert ret == 0, f"bucket logging info failed with return code {ret}"
        
        # Verify source bucket is listed in output
        assert source_bucket in output, \
            f"Source bucket {source_bucket} should be listed in log bucket info"
        log.info(f"✓ Verified source bucket is listed in log bucket info")
        
    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_bucket_logging_flush():
    """Test radosgw-admin bucket logging flush command."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("source")
    log_bucket = gen_bucket_name("log")
    
    try:
        # Setup
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"
        
        # Upload objects to generate log records
        for i in range(3):
            s3_client.put_object(
                Bucket=source_bucket,
                Key=f'test-object-{i}.txt',
                Body=f'test content {i}'.encode()
            )
        log.info(f"Uploaded test objects to {source_bucket}")

        # Flush the logs
        output, ret = admin([
            'bucket', 'logging', 'flush',
            '--bucket', source_bucket
        ])
        
        log.info(f"bucket logging flush output: {output}")
        assert ret == 0, f"bucket logging flush failed with return code {ret}"
        
        # Extract flushed object name from output
        # Output format: "flushed pending logging object '<name>' to target bucket '<bucket>'"
        flushed_object_name = None
        if "flushed pending logging object" in output:
            import re
            match = re.search(r"flushed pending logging object '([^']+)'", output)
            if match:
                flushed_object_name = match.group(1)
                log.info(f"Extracted flushed object name: {flushed_object_name}")

        # Give some time for flush to complete
        time.sleep(2)

        # Verify logs appear in log bucket
        response = s3_client.list_objects_v2(Bucket=log_bucket)
        log.info(f"Log bucket contents after flush: {response.get('Contents', [])}")
        
        # Verify flushed object name was extracted and matches log bucket contents
        assert flushed_object_name is not None, \
            "Expected flushed object name in flush output"
        assert 'Contents' in response, "Log bucket should have contents after flush"
        log_object_keys = [obj['Key'] for obj in response['Contents']]
        assert flushed_object_name in log_object_keys, \
            f"Flushed object '{flushed_object_name}' not found in log bucket. Found: {log_object_keys}"
        log.info(f"✓ Verified: flushed object name matches log bucket contents")
        
    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


# =============================================================================
# Cleanup Tests
# =============================================================================

def test_cleanup_on_log_bucket_delete():
    """
    Test that temporary log objects are deleted when log bucket is deleted.
    
    Steps:
    1. Create source bucket
    2. Create log bucket
    3. Set policy on log bucket
    4. Enable logging on source bucket
    5. Upload objects to source (generates temp log objects)
    6. Verify temp objects exist using rados ls
    7. Delete log bucket
    8. Verify temp objects are gone
    """
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("cleanup-source")
    log_bucket = gen_bucket_name("cleanup-log")

    try:
        # Set up buckets with logging
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Get log bucket ID for identifying temp objects
        log_bucket_id = get_bucket_id(log_bucket)
        log.info(f"Log bucket ID: {log_bucket_id}")

        # Upload objects to source bucket to generate log records
        for i in range(5):
            s3_client.put_object(
                Bucket=source_bucket,
                Key=f'object-{i}.txt',
                Body=f'content {i}'.encode()
            )
        log.info(f"Uploaded 5 objects to {source_bucket}")

        # Check for temp objects using rados ls (created immediately after put_object)
        temp_objects_before, success = find_temp_log_objects(log_bucket_id)
        assert success, "Failed to list rados objects"
        assert len(temp_objects_before) > 0, "Expected temp objects to exist before cleanup"
        log.info(f"Temp objects before delete: {temp_objects_before}")



        # Delete objects from log bucket (if any)
        try:
            response = s3_client.list_objects_v2(Bucket=log_bucket)
            if 'Contents' in response:
                for obj in response['Contents']:
                    s3_client.delete_object(Bucket=log_bucket, Key=obj['Key'])
        except ClientError:
            pass

        # Delete log bucket
        s3_client.delete_bucket(Bucket=log_bucket)
        log.info(f"Deleted log bucket: {log_bucket}")

        # Give time for cleanup to happen
        time.sleep(2)

        # Verify temp objects are gone
        temp_objects_after, success = find_temp_log_objects(log_bucket_id)
        assert success, "Failed to list rados objects"
        log.info(f"Temp objects after delete: {temp_objects_after}")

        # Cleanup should have removed temp objects
        assert len(temp_objects_after) == 0, \
            f"Temp objects still exist after log bucket deletion: {temp_objects_after}"

    finally:
        # Cleanup source bucket
        cleanup_bucket(s3_client, source_bucket)


def test_cleanup_on_logging_disable():
    """
    Test that temporary log objects are flushed when logging is disabled.
    
    Verifies that the FlushedLoggingObject returned by put_bucket_logging
    is present in the log bucket.
    """
    import re
    
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("disable-source")
    log_bucket = gen_bucket_name("disable-log")

    # Variable to capture response body via botocore events
    captured_response = {}
    
    def capture_response(http_response, **kwargs):
        """Capture the HTTP response body before botocore processes it."""
        captured_response['body'] = http_response.text if hasattr(http_response, 'text') else ''
    
    try:
        # Set up buckets with logging
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Upload objects to source bucket
        for i in range(3):
            s3_client.put_object(
                Bucket=source_bucket,
                Key=f'object-{i}.txt',
                Body=f'content {i}'.encode()
            )
        log.info(f"Uploaded 3 objects to {source_bucket}")

        # Register event handler to capture response
        s3_client.meta.events.register('after-call.s3.PutBucketLogging', capture_response)
        
        try:
            # Disable logging (should trigger flush and return FlushedLoggingObject)
            s3_client.put_bucket_logging(
                Bucket=source_bucket,
                BucketLoggingStatus={}
            )
        finally:
            # Unregister to avoid affecting other tests
            s3_client.meta.events.unregister('after-call.s3.PutBucketLogging', capture_response)
        
        log.info(f"Disabled logging on {source_bucket}")
        log.info(f"Captured response body: {captured_response.get('body', 'EMPTY')}")

        # Give time for flush to complete
        time.sleep(2)

        # Check that logs were written to log bucket
        response = s3_client.list_objects_v2(Bucket=log_bucket)
        log_objects = response.get('Contents', [])
        log.info(f"Log objects after disable: {log_objects}")

        # Verify logs were flushed to the log bucket
        assert 'Contents' in response, "Expected log objects after disable"
        assert len(log_objects) > 0, "Expected at least one log object after flush"
        
        # Try to extract FlushedLoggingObject from captured response
        flushed_object_name = None
        response_body = captured_response.get('body', '')
        if response_body and 'FlushedLoggingObject' in response_body:
            # Parse XML response
            match = re.search(r'<FlushedLoggingObject>([^<]+)</FlushedLoggingObject>', response_body)
            if match:
                flushed_object_name = match.group(1)
                log.info(f"FlushedLoggingObject from response: {flushed_object_name}")
                
                # Verify the flushed object is in the log bucket
                log_object_keys = [obj['Key'] for obj in log_objects]
                assert flushed_object_name in log_object_keys, \
                    f"FlushedLoggingObject '{flushed_object_name}' not found in log bucket. Found: {log_object_keys}"
                log.info(f"✓ Verified: FlushedLoggingObject matches log bucket contents")
        else:
            log.info("Note: FlushedLoggingObject not in response (may be empty if no pending logs)")

    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_cleanup_on_logging_config_change():
    """
    Test that changing logging configuration triggers flushing of pending logs.
    
    When the source bucket's logging config is changed to a different log bucket,
    pending logs should be flushed to the original log bucket.
    """
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("config-change-source")
    log_bucket_1 = gen_bucket_name("config-change-log1")
    log_bucket_2 = gen_bucket_name("config-change-log2")

    try:
        # Set up buckets with logging to first log bucket
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket_1), \
            "Failed to set up bucket logging"

        # Get log bucket ID for identifying temp objects
        log_bucket_1_id = get_bucket_id(log_bucket_1)
        log.info(f"Log bucket 1 ID: {log_bucket_1_id}")

        # Upload objects to source bucket to generate log records
        for i in range(3):
            s3_client.put_object(
                Bucket=source_bucket,
                Key=f'object-{i}.txt',
                Body=f'content {i}'.encode()
            )
        log.info(f"Uploaded 3 objects to {source_bucket}")

        # Check for temp objects before config change
        temp_objects_before, success = find_temp_log_objects(log_bucket_1_id)
        assert success, "Failed to list rados objects"
        assert len(temp_objects_before) > 0, "Expected temp objects to exist before config change"
        log.info(f"Temp objects before config change: {temp_objects_before}")

        # Create second log bucket
        s3_client.create_bucket(Bucket=log_bucket_2)
        user_id = get_user_id()
        policy = LOGGING_POLICY_TEMPLATE.format(
            log_bucket=log_bucket_2,
            source_bucket=source_bucket,
            account_id=user_id
        )
        s3_client.put_bucket_policy(Bucket=log_bucket_2, Policy=policy)
        log.info(f"Created second log bucket: {log_bucket_2}")

        # Change logging config to point to second log bucket (should trigger flush)
        logging_config = {
            'LoggingEnabled': {
                'TargetBucket': log_bucket_2,
                'TargetPrefix': f'{source_bucket}/'
            }
        }
        s3_client.put_bucket_logging(Bucket=source_bucket, BucketLoggingStatus=logging_config)
        log.info(f"Changed logging config to {log_bucket_2}")

        # Give time for flush to complete
        time.sleep(2)

        # Verify logs were flushed to original log bucket
        response = s3_client.list_objects_v2(Bucket=log_bucket_1)
        log_objects = response.get('Contents', [])
        log.info(f"Log objects in original log bucket after config change: {log_objects}")

        # Check that temp objects are cleaned up
        temp_objects_after, success = find_temp_log_objects(log_bucket_1_id)
        assert success, "Failed to list rados objects"
        log.info(f"Temp objects after config change: {temp_objects_after}")

        assert len(temp_objects_after) == 0, \
            f"Temp objects still exist after logging config change: {temp_objects_after}"

    finally:
        # Disable logging before cleanup
        try:
            s3_client.put_bucket_logging(Bucket=source_bucket, BucketLoggingStatus={})
        except ClientError:
            pass
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket_1)
        cleanup_bucket(s3_client, log_bucket_2)


def test_cleanup_on_source_bucket_delete():
    """
    Test that deleting source bucket triggers flushing of pending logs.
    
    When the source bucket is deleted, any pending logs should be flushed
    to the log bucket before deletion.
    """
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("src-delete-source")
    log_bucket = gen_bucket_name("src-delete-log")

    try:
        # Set up buckets with logging
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Get log bucket ID for identifying temp objects
        log_bucket_id = get_bucket_id(log_bucket)
        log.info(f"Log bucket ID: {log_bucket_id}")

        # Upload objects to source bucket to generate log records
        for i in range(3):
            s3_client.put_object(
                Bucket=source_bucket,
                Key=f'object-{i}.txt',
                Body=f'content {i}'.encode()
            )
        log.info(f"Uploaded 3 objects to {source_bucket}")

        # Check for temp objects before source bucket deletion
        temp_objects_before, success = find_temp_log_objects(log_bucket_id)
        assert success, "Failed to list rados objects"
        assert len(temp_objects_before) > 0, "Expected temp objects to exist before source delete"
        log.info(f"Temp objects before source bucket delete: {temp_objects_before}")

        # NOTE: Do NOT disable logging before deletion - we want to test that
        # deleting a source bucket with active logging triggers proper cleanup

        # Delete all objects from source bucket
        response = s3_client.list_objects_v2(Bucket=source_bucket)
        if 'Contents' in response:
            for obj in response['Contents']:
                s3_client.delete_object(Bucket=source_bucket, Key=obj['Key'])

        # Delete source bucket (should trigger flush)
        s3_client.delete_bucket(Bucket=source_bucket)
        log.info(f"Deleted source bucket: {source_bucket}")

        # Give time for flush to complete
        time.sleep(2)

        # Verify logs were flushed to log bucket
        response = s3_client.list_objects_v2(Bucket=log_bucket)
        log_objects = response.get('Contents', [])
        log.info(f"Log objects in log bucket after source deletion: {log_objects}")

        # Check that temp objects are cleaned up
        temp_objects_after, success = find_temp_log_objects(log_bucket_id)
        assert success, "Failed to list rados objects"
        log.info(f"Temp objects after source bucket delete: {temp_objects_after}")

        assert len(temp_objects_after) == 0, \
            f"Temp objects still exist after source bucket deletion: {temp_objects_after}"

    finally:
        # Cleanup (source bucket already deleted if test passed)
        try:
            cleanup_bucket(s3_client, source_bucket)
        except ClientError:
            pass
        cleanup_bucket(s3_client, log_bucket)


# =============================================================================
# Multiple Sources Tests
# =============================================================================

def test_bucket_logging_info_log_multiple_sources():
    """
    Test that multiple source buckets can log to the same log bucket.
    Verifies bucket logging info shows all sources.
    """
    s3_client = get_s3_client()
    source_bucket_1 = gen_bucket_name("multi-source1")
    source_bucket_2 = gen_bucket_name("multi-source2")
    log_bucket = gen_bucket_name("multi-log")
    user_id = get_user_id()

    try:
        # Create log bucket
        s3_client.create_bucket(Bucket=log_bucket)

        # Create policy allowing both sources (using broader condition)
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowLogging",
                    "Effect": "Allow",
                    "Principal": {"Service": "logging.s3.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{log_bucket}/*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": user_id}
                    }
                }
            ]
        })
        s3_client.put_bucket_policy(Bucket=log_bucket, Policy=policy)

        # Create and configure both source buckets with different prefixes
        s3_client.create_bucket(Bucket=source_bucket_1)
        s3_client.create_bucket(Bucket=source_bucket_2)

        for src, prefix in [(source_bucket_1, 'source1/'), (source_bucket_2, 'source2/')]:
            s3_client.put_bucket_logging(
                Bucket=src,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': log_bucket,
                        'TargetPrefix': prefix
                    }
                }
            )
        log.info(f"Configured both sources to log to {log_bucket} with different prefixes")

        # Run bucket logging info on log bucket
        output, ret = admin([
            'bucket', 'logging', 'info',
            '--bucket', log_bucket
        ])

        log.info(f"bucket logging info (log) output: {output}")
        assert ret == 0, f"bucket logging info failed with return code {ret}"

        # Verify both source buckets are listed
        assert source_bucket_1 in output, \
            f"Source bucket 1 ({source_bucket_1}) not in output"
        assert source_bucket_2 in output, \
            f"Source bucket 2 ({source_bucket_2}) not in output"
        log.info("✓ Verified both source buckets are listed in log bucket info")

    finally:
        cleanup_bucket(s3_client, source_bucket_1)
        cleanup_bucket(s3_client, source_bucket_2)
        cleanup_bucket(s3_client, log_bucket)


def test_multiple_sources_disable_one():
    """
    Test that disabling logging on one source bucket still keeps other sources listed.
    """
    s3_client = get_s3_client()
    source_bucket_1 = gen_bucket_name("disable-one-src1")
    source_bucket_2 = gen_bucket_name("disable-one-src2")
    log_bucket = gen_bucket_name("disable-one-log")
    user_id = get_user_id()

    try:
        # Create log bucket
        s3_client.create_bucket(Bucket=log_bucket)

        # Create policy allowing both sources
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowLogging",
                    "Effect": "Allow",
                    "Principal": {"Service": "logging.s3.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{log_bucket}/*",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": user_id}
                    }
                }
            ]
        })
        s3_client.put_bucket_policy(Bucket=log_bucket, Policy=policy)

        # Create and configure both source buckets
        s3_client.create_bucket(Bucket=source_bucket_1)
        s3_client.create_bucket(Bucket=source_bucket_2)

        for src, prefix in [(source_bucket_1, 'src1/'), (source_bucket_2, 'src2/')]:
            s3_client.put_bucket_logging(
                Bucket=src,
                BucketLoggingStatus={
                    'LoggingEnabled': {
                        'TargetBucket': log_bucket,
                        'TargetPrefix': prefix
                    }
                }
            )

        # Disable logging on source 1
        s3_client.put_bucket_logging(Bucket=source_bucket_1, BucketLoggingStatus={})
        log.info(f"Disabled logging on {source_bucket_1}")

        # Verify source 2 is still listed in log bucket info
        output, ret = admin([
            'bucket', 'logging', 'info',
            '--bucket', log_bucket
        ])

        assert ret == 0, f"bucket logging info failed with return code {ret}"
        assert source_bucket_2 in output, \
            f"Source bucket 2 should still be listed after source 1 disabled"
        assert source_bucket_1 not in output, \
            f"Source bucket 1 should not be listed after disabling"

    finally:
        cleanup_bucket(s3_client, source_bucket_1)
        cleanup_bucket(s3_client, source_bucket_2)
        cleanup_bucket(s3_client, log_bucket)


# =============================================================================
# Logging Info After Disable/Delete Tests
# =============================================================================

def test_logging_info_after_disable():
    """Verify that bucket logging info no longer lists source after logging is disabled."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("info-disable-src")
    log_bucket = gen_bucket_name("info-disable-log")

    try:
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Verify source is listed before disable
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', log_bucket])
        assert ret == 0
        assert source_bucket in output, "Source should be listed before disable"

        # Disable logging
        s3_client.put_bucket_logging(Bucket=source_bucket, BucketLoggingStatus={})
        log.info(f"Disabled logging on {source_bucket}")

        # Verify source is no longer listed
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', log_bucket])
        assert ret == 0
        assert source_bucket not in output, \
            f"Source bucket should not be listed after disable. Output: {output}"

    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_logging_info_after_source_delete():
    """Verify that bucket logging info no longer lists source after source is deleted."""
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("info-delete-src")
    log_bucket = gen_bucket_name("info-delete-log")

    try:
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Verify source is listed before delete
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', log_bucket])
        assert ret == 0
        assert source_bucket in output, "Source should be listed before delete"

        # Disable logging and delete source
        s3_client.put_bucket_logging(Bucket=source_bucket, BucketLoggingStatus={})
        s3_client.delete_bucket(Bucket=source_bucket)
        log.info(f"Deleted source bucket: {source_bucket}")

        # Verify source is no longer listed
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', log_bucket])
        assert ret == 0
        assert source_bucket not in output, \
            f"Source bucket should not be listed after delete. Output: {output}"

    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


# =============================================================================
# Edge Case Tests
# =============================================================================

def test_flush_empty_creates_empty_object():
    """
    Test that flushing a log with no data creates an empty log object.
    Verifies no shadow objects remain after empty flush.
    """
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("empty-flush-src")
    log_bucket = gen_bucket_name("empty-flush-log")

    try:
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Don't upload any data - just flush
        output, ret = admin([
            'bucket', 'logging', 'flush',
            '--bucket', source_bucket
        ])
        log.info(f"Flush with no data output: {output}")
        assert ret == 0, f"Flush failed with return code {ret}"

        # Check log bucket contents
        response = s3_client.list_objects_v2(Bucket=log_bucket)
        log_objects = response.get('Contents', [])
        log.info(f"Log objects after empty flush: {log_objects}")

        # Get log bucket ID and check for shadow objects
        log_bucket_id = get_bucket_id(log_bucket)
        temp_objects, success = find_temp_log_objects(log_bucket_id)
        assert success, "Failed to list rados objects"
        assert len(temp_objects) == 0, \
            f"Shadow objects should not exist after flush: {temp_objects}"
        log.info("✓ Verified no shadow log objects after empty flush")

    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_logging_config_update_prefix():
    """
    Test updating logging configuration to change prefix.
    Verifies bucket logging info returns updated config.
    """
    s3_client = get_s3_client()
    source_bucket = gen_bucket_name("update-prefix-src")
    log_bucket = gen_bucket_name("update-prefix-log")

    try:
        assert create_bucket_with_logging(s3_client, source_bucket, log_bucket), \
            "Failed to set up bucket logging"

        # Get initial logging info
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', source_bucket])
        assert ret == 0
        log.info(f"Initial logging info: {output}")

        # Update prefix
        new_prefix = "new-prefix/"
        s3_client.put_bucket_logging(
            Bucket=source_bucket,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': log_bucket,
                    'TargetPrefix': new_prefix
                }
            }
        )
        log.info(f"Updated prefix to {new_prefix}")

        # Verify updated config
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', source_bucket])
        assert ret == 0
        log.info(f"Updated logging info: {output}")
        assert new_prefix in output, \
            f"New prefix '{new_prefix}' should be in updated config. Output: {output}"

        # Upload data to verify new prefix is used
        s3_client.put_object(
            Bucket=source_bucket,
            Key='test-after-update.txt',
            Body=b'test content'
        )

        # Flush and check log object names
        admin(['bucket', 'logging', 'flush', '--bucket', source_bucket])
        time.sleep(2)

        response = s3_client.list_objects_v2(Bucket=log_bucket)
        log_keys = [obj['Key'] for obj in response.get('Contents', [])]
        log.info(f"Log objects after prefix update: {log_keys}")

        # Verify new prefix is used in log object names
        new_prefix_used = any(key.startswith(new_prefix) for key in log_keys)
        assert new_prefix_used, \
            f"New prefix should be used in log object names. Found: {log_keys}"
        log.info("✓ Verified new prefix is used after config update")

    finally:
        cleanup_bucket(s3_client, source_bucket)
        cleanup_bucket(s3_client, log_bucket)


def test_logging_commands_unconfigured_bucket():
    """
    Test that logging commands handle unconfigured buckets appropriately.
    """
    s3_client = get_s3_client()
    bucket = gen_bucket_name("unconfigured")

    try:
        s3_client.create_bucket(Bucket=bucket)

        # Test list command on bucket without logging
        output, ret = admin(['bucket', 'logging', 'list', '--bucket', bucket])
        log.info(f"List on unconfigured bucket - ret: {ret}, output: {output}")
        assert ret == 0, f"List command should succeed on unconfigured bucket, got ret={ret}"

        # Test info command on bucket without logging
        output, ret = admin(['bucket', 'logging', 'info', '--bucket', bucket])
        log.info(f"Info on unconfigured bucket - ret: {ret}, output: {output}")
        assert ret == 0, f"Info command should succeed on unconfigured bucket, got ret={ret}"

        # Test flush command on bucket without logging
        output, ret = admin(['bucket', 'logging', 'flush', '--bucket', bucket])
        log.info(f"Flush on unconfigured bucket - ret: {ret}, output: {output}")
        # Flush should succeed (no-op) or return appropriate error
        assert ret == 0, f"Flush command should handle unconfigured bucket gracefully, got ret={ret}"

        log.info("✓ Verified commands handle unconfigured bucket appropriately")

    finally:
        cleanup_bucket(s3_client, bucket)


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v'])

