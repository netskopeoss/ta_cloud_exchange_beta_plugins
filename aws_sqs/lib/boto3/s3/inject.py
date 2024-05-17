# Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# https://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import copy as python_copy

from botocore.exceptions import ClientError

from boto3 import utils
from boto3.s3.transfer import (
    ProgressCallbackInvoker,
    S3Transfer,
    TransferConfig,
    create_transfer_manager,
)


def inject_s3_transfer_methods(class_attributes, **kwargs):
    utils.inject_attribute(class_attributes, "upload_file", upload_file)
    utils.inject_attribute(class_attributes, "download_file", download_file)
    utils.inject_attribute(class_attributes, "copy", copy)
    utils.inject_attribute(class_attributes, "upload_fileobj", upload_fileobj)
    utils.inject_attribute(class_attributes, "download_fileobj", download_fileobj)


def inject_bucket_methods(class_attributes, **kwargs):
    utils.inject_attribute(class_attributes, "load", bucket_load)
    utils.inject_attribute(class_attributes, "upload_file", bucket_upload_file)
    utils.inject_attribute(class_attributes, "download_file", bucket_download_file)
    utils.inject_attribute(class_attributes, "copy", bucket_copy)
    utils.inject_attribute(class_attributes, "upload_fileobj", bucket_upload_fileobj)
    utils.inject_attribute(
        class_attributes, "download_fileobj", bucket_download_fileobj
    )


def inject_object_methods(class_attributes, **kwargs):
    utils.inject_attribute(class_attributes, "upload_file", object_upload_file)
    utils.inject_attribute(class_attributes, "download_file", object_download_file)
    utils.inject_attribute(class_attributes, "copy", object_copy)
    utils.inject_attribute(class_attributes, "upload_fileobj", object_upload_fileobj)
    utils.inject_attribute(
        class_attributes, "download_fileobj", object_download_fileobj
    )


def inject_object_summary_methods(class_attributes, **kwargs):
    utils.inject_attribute(class_attributes, "load", object_summary_load)


def bucket_load(self, *args, **kwargs):
    """
    Calls s3.Client.list_buckets() to update the attributes of the Bucket
    resource.
    """
    # The docstring above is phrased this way to match what the autogenerated
    # docs produce.

    # We can't actually get the bucket's attributes from a HeadBucket,
    # so we need to use a ListBuckets and search for our bucket.
    # However, we may fail if we lack permissions to ListBuckets
    # or the bucket is in another account. In which case, creation_date
    # will be None.
    self.meta.data = {}
    try:
        response = self.meta.client.list_buckets()
        for bucket_data in response["Buckets"]:
            if bucket_data["Name"] == self.name:
                self.meta.data = bucket_data
                break
    except ClientError as e:
        if not e.response.get("Error", {}).get("Code") == "AccessDenied":
            raise


def object_summary_load(self, *args, **kwargs):
    """
    Calls s3.Client.head_object to update the attributes of the ObjectSummary
    resource.
    """
    response = self.meta.client.head_object(Bucket=self.bucket_name, Key=self.key)
    if "ContentLength" in response:
        response["Size"] = response.pop("ContentLength")
    self.meta.data = response


def upload_file(
    self, Filename, Bucket, Key, ExtraArgs=None, Callback=None, Config=None
):
    """Upload a file to an S3 object.

    Usage::

        import boto3
        s3 = boto3.client('s3')
        s3.upload_file('/tmp/hello.txt', 'mybucket', 'hello.txt')

    Similar behavior as S3Transfer's upload_file() method, except that
    argument names are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Filename: str
    :param Filename: The path to the file to upload.

    :type Bucket: str
    :param Bucket: The name of the bucket to upload to.

    :type Key: str
    :param Key: The name of the key to upload to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    with S3Transfer(self, Config) as transfer:
        return transfer.upload_file(
            filename=Filename,
            bucket=Bucket,
            key=Key,
            extra_args=ExtraArgs,
            callback=Callback,
        )


def download_file(
    self, Bucket, Key, Filename, ExtraArgs=None, Callback=None, Config=None
):
    """Download an S3 object to a file.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        s3.meta.client.download_file('mybucket', 'hello.txt', '/tmp/hello.txt')

    Similar behavior as S3Transfer's download_file() method,
    except that parameters are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Bucket: str
    :param Bucket: The name of the bucket to download from.

    :type Key: str
    :param Key: The name of the key to download from.

    :type Filename: str
    :param Filename: The path to the file to download to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    with S3Transfer(self, Config) as transfer:
        return transfer.download_file(
            bucket=Bucket,
            key=Key,
            filename=Filename,
            extra_args=ExtraArgs,
            callback=Callback,
        )


def bucket_upload_file(self, Filename, Key, ExtraArgs=None, Callback=None, Config=None):
    """Upload a file to an S3 object.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        s3.Bucket('mybucket').upload_file('/tmp/hello.txt', 'hello.txt')

    Similar behavior as S3Transfer's upload_file() method,
    except that parameters are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Filename: str
    :param Filename: The path to the file to upload.

    :type Key: str
    :param Key: The name of the key to upload to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    return self.meta.client.upload_file(
        Filename=Filename,
        Bucket=self.name,
        Key=Key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def bucket_download_file(
    self, Key, Filename, ExtraArgs=None, Callback=None, Config=None
):
    """Download an S3 object to a file.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        s3.Bucket('mybucket').download_file('hello.txt', '/tmp/hello.txt')

    Similar behavior as S3Transfer's download_file() method,
    except that parameters are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Key: str
    :param Key: The name of the key to download from.

    :type Filename: str
    :param Filename: The path to the file to download to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    return self.meta.client.download_file(
        Bucket=self.name,
        Key=Key,
        Filename=Filename,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def object_upload_file(self, Filename, ExtraArgs=None, Callback=None, Config=None):
    """Upload a file to an S3 object.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        s3.Object('mybucket', 'hello.txt').upload_file('/tmp/hello.txt')

    Similar behavior as S3Transfer's upload_file() method,
    except that parameters are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Filename: str
    :param Filename: The path to the file to upload.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    return self.meta.client.upload_file(
        Filename=Filename,
        Bucket=self.bucket_name,
        Key=self.key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def object_download_file(self, Filename, ExtraArgs=None, Callback=None, Config=None):
    """Download an S3 object to a file.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        s3.Object('mybucket', 'hello.txt').download_file('/tmp/hello.txt')

    Similar behavior as S3Transfer's download_file() method,
    except that parameters are capitalized. Detailed examples can be found at
    :ref:`S3Transfer's Usage <ref_s3transfer_usage>`.

    :type Filename: str
    :param Filename: The path to the file to download to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        transfer.
    """
    return self.meta.client.download_file(
        Bucket=self.bucket_name,
        Key=self.key,
        Filename=Filename,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def copy(
    self,
    CopySource,
    Bucket,
    Key,
    ExtraArgs=None,
    Callback=None,
    SourceClient=None,
    Config=None,
):
    """Copy an object from one S3 location to another.

    This is a managed transfer which will perform a multipart copy in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        copy_source = {
            'Bucket': 'mybucket',
            'Key': 'mykey'
        }
        s3.meta.client.copy(copy_source, 'otherbucket', 'otherkey')

    :type CopySource: dict
    :param CopySource: The name of the source bucket, key name of the
        source object, and optional version ID of the source object. The
        dictionary format is:
        ``{'Bucket': 'bucket', 'Key': 'key', 'VersionId': 'id'}``. Note
        that the ``VersionId`` key is optional and may be omitted.

    :type Bucket: str
    :param Bucket: The name of the bucket to copy to

    :type Key: str
    :param Key: The name of the key to copy to

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the copy.

    :type SourceClient: botocore or boto3 Client
    :param SourceClient: The client to be used for operation that
        may happen at the source object. For example, this client is
        used for the head_object that determines the size of the copy.
        If no client is provided, the current client is used as the client
        for the source object.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        copy.
    """
    subscribers = None
    if Callback is not None:
        subscribers = [ProgressCallbackInvoker(Callback)]

    config = Config
    if config is None:
        config = TransferConfig()

    # copy is not supported in the CRT
    new_config = python_copy.copy(config)
    new_config.preferred_transfer_client = "classic"

    with create_transfer_manager(self, new_config) as manager:
        future = manager.copy(
            copy_source=CopySource,
            bucket=Bucket,
            key=Key,
            extra_args=ExtraArgs,
            subscribers=subscribers,
            source_client=SourceClient,
        )
        return future.result()


def bucket_copy(
    self,
    CopySource,
    Key,
    ExtraArgs=None,
    Callback=None,
    SourceClient=None,
    Config=None,
):
    """Copy an object from one S3 location to an object in this bucket.

    This is a managed transfer which will perform a multipart copy in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        copy_source = {
            'Bucket': 'mybucket',
            'Key': 'mykey'
        }
        bucket = s3.Bucket('otherbucket')
        bucket.copy(copy_source, 'otherkey')

    :type CopySource: dict
    :param CopySource: The name of the source bucket, key name of the
        source object, and optional version ID of the source object. The
        dictionary format is:
        ``{'Bucket': 'bucket', 'Key': 'key', 'VersionId': 'id'}``. Note
        that the ``VersionId`` key is optional and may be omitted.

    :type Key: str
    :param Key: The name of the key to copy to

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the copy.

    :type SourceClient: botocore or boto3 Client
    :param SourceClient: The client to be used for operation that
        may happen at the source object. For example, this client is
        used for the head_object that determines the size of the copy.
        If no client is provided, the current client is used as the client
        for the source object.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        copy.
    """
    return self.meta.client.copy(
        CopySource=CopySource,
        Bucket=self.name,
        Key=Key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        SourceClient=SourceClient,
        Config=Config,
    )


def object_copy(
    self,
    CopySource,
    ExtraArgs=None,
    Callback=None,
    SourceClient=None,
    Config=None,
):
    """Copy an object from one S3 location to this object.

    This is a managed transfer which will perform a multipart copy in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        copy_source = {
            'Bucket': 'mybucket',
            'Key': 'mykey'
        }
        bucket = s3.Bucket('otherbucket')
        obj = bucket.Object('otherkey')
        obj.copy(copy_source)

    :type CopySource: dict
    :param CopySource: The name of the source bucket, key name of the
        source object, and optional version ID of the source object. The
        dictionary format is:
        ``{'Bucket': 'bucket', 'Key': 'key', 'VersionId': 'id'}``. Note
        that the ``VersionId`` key is optional and may be omitted.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the copy.

    :type SourceClient: botocore or boto3 Client
    :param SourceClient: The client to be used for operation that
        may happen at the source object. For example, this client is
        used for the head_object that determines the size of the copy.
        If no client is provided, the current client is used as the client
        for the source object.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        copy.
    """
    return self.meta.client.copy(
        CopySource=CopySource,
        Bucket=self.bucket_name,
        Key=self.key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        SourceClient=SourceClient,
        Config=Config,
    )


def upload_fileobj(
    self, Fileobj, Bucket, Key, ExtraArgs=None, Callback=None, Config=None
):
    """Upload a file-like object to S3.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart upload in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.client('s3')

        with open('filename', 'rb') as data:
            s3.upload_fileobj(data, 'mybucket', 'mykey')

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to upload. At a minimum, it must
        implement the `read` method, and must return bytes.

    :type Bucket: str
    :param Bucket: The name of the bucket to upload to.

    :type Key: str
    :param Key: The name of the key to upload to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        upload.
    """
    if not hasattr(Fileobj, "read"):
        raise ValueError("Fileobj must implement read")

    subscribers = None
    if Callback is not None:
        subscribers = [ProgressCallbackInvoker(Callback)]

    config = Config
    if config is None:
        config = TransferConfig()

    with create_transfer_manager(self, config) as manager:
        future = manager.upload(
            fileobj=Fileobj,
            bucket=Bucket,
            key=Key,
            extra_args=ExtraArgs,
            subscribers=subscribers,
        )
        return future.result()


def bucket_upload_fileobj(
    self, Fileobj, Key, ExtraArgs=None, Callback=None, Config=None
):
    """Upload a file-like object to this bucket.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart upload in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        bucket = s3.Bucket('mybucket')

        with open('filename', 'rb') as data:
            bucket.upload_fileobj(data, 'mykey')

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to upload. At a minimum, it must
        implement the `read` method, and must return bytes.

    :type Key: str
    :param Key: The name of the key to upload to.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        upload.
    """
    return self.meta.client.upload_fileobj(
        Fileobj=Fileobj,
        Bucket=self.name,
        Key=Key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def object_upload_fileobj(self, Fileobj, ExtraArgs=None, Callback=None, Config=None):
    """Upload a file-like object to this object.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart upload in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        bucket = s3.Bucket('mybucket')
        obj = bucket.Object('mykey')

        with open('filename', 'rb') as data:
            obj.upload_fileobj(data)

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to upload. At a minimum, it must
        implement the `read` method, and must return bytes.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed upload arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_UPLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the upload.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        upload.
    """
    return self.meta.client.upload_fileobj(
        Fileobj=Fileobj,
        Bucket=self.bucket_name,
        Key=self.key,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def download_fileobj(
    self, Bucket, Key, Fileobj, ExtraArgs=None, Callback=None, Config=None
):
    """Download an object from S3 to a file-like object.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart download in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.client('s3')

        with open('filename', 'wb') as data:
            s3.download_fileobj('mybucket', 'mykey', data)

    :type Bucket: str
    :param Bucket: The name of the bucket to download from.

    :type Key: str
    :param Key: The name of the key to download from.

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to download into. At a minimum, it must
        implement the `write` method and must accept bytes.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        download.
    """
    if not hasattr(Fileobj, "write"):
        raise ValueError("Fileobj must implement write")

    subscribers = None
    if Callback is not None:
        subscribers = [ProgressCallbackInvoker(Callback)]

    config = Config
    if config is None:
        config = TransferConfig()

    with create_transfer_manager(self, config) as manager:
        future = manager.download(
            bucket=Bucket,
            key=Key,
            fileobj=Fileobj,
            extra_args=ExtraArgs,
            subscribers=subscribers,
        )
        return future.result()


def bucket_download_fileobj(
    self, Key, Fileobj, ExtraArgs=None, Callback=None, Config=None
):
    """Download an object from this bucket to a file-like-object.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart download in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        bucket = s3.Bucket('mybucket')

        with open('filename', 'wb') as data:
            bucket.download_fileobj('mykey', data)

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to download into. At a minimum, it must
        implement the `write` method and must accept bytes.

    :type Key: str
    :param Key: The name of the key to download from.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        download.
    """
    return self.meta.client.download_fileobj(
        Bucket=self.name,
        Key=Key,
        Fileobj=Fileobj,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )


def object_download_fileobj(self, Fileobj, ExtraArgs=None, Callback=None, Config=None):
    """Download this object from S3 to a file-like object.

    The file-like object must be in binary mode.

    This is a managed transfer which will perform a multipart download in
    multiple threads if necessary.

    Usage::

        import boto3
        s3 = boto3.resource('s3')
        bucket = s3.Bucket('mybucket')
        obj = bucket.Object('mykey')

        with open('filename', 'wb') as data:
            obj.download_fileobj(data)

    :type Fileobj: a file-like object
    :param Fileobj: A file-like object to download into. At a minimum, it must
        implement the `write` method and must accept bytes.

    :type ExtraArgs: dict
    :param ExtraArgs: Extra arguments that may be passed to the
        client operation. For allowed download arguments see
        boto3.s3.transfer.S3Transfer.ALLOWED_DOWNLOAD_ARGS.

    :type Callback: function
    :param Callback: A method which takes a number of bytes transferred to
        be periodically called during the download.

    :type Config: boto3.s3.transfer.TransferConfig
    :param Config: The transfer configuration to be used when performing the
        download.
    """
    return self.meta.client.download_fileobj(
        Bucket=self.bucket_name,
        Key=self.key,
        Fileobj=Fileobj,
        ExtraArgs=ExtraArgs,
        Callback=Callback,
        Config=Config,
    )
