# Blob Upload Connector

Writes a subset of attributes/fields to a blob storage backend
(such as Google Cloud Storage, Amazon S3, Azure Blob, etc.),
replacing the matched attributes/fields with a [reference](https://github.com/open-telemetry/semantic-conventions/issues/1428) to where
the data was queued to be written in the blob storage destination.
