// Package "backend" provides utilities for writing to a general blob storage system.
//
// The "cdk.go" file provides implementations supported via "Cloud Development Kit":
// https://pkg.go.dev/gocloud.dev/blob
package backend

import (
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
)

// An implementation of "BlobStorageBackend" that is implemented using the CDK.
type cdkBlobStorageBackend struct {}

// "splitBucketAndPath" handles splitting the bucket URI from the path.
func splitBucketAndPath(uri string) (bucketUri string, path string) {
	scheme, rest := strings.SplitN(uri, "://", 1)
	components := strings.Split(rest, "/")
	bucketUri := scheme + "://" + components[0]
	path := strings.Join(components[1:], "/")
	return (bucketUri, path)
}

// "Upload" implements the "BlobStorageBackend.Upload" interface operation.
func (c *cdkBlobStorageBackend) Upload(ctx context.Context, uri string, data []byte, metadata UploadMetadata) (err) {
	bucketUri, path := splitBucketAndPath(uri)
	bucket, err := blob.OpenBucket(ctx, bucketUri)
	if err != nil {
		return err
	}
	defer bucket.Close()

	opts := blob.WriterOptions {
		// The content type supplied in the upload metadata.
		ContentType: metadata.ContentType(),

		// Disabled to prevent duplicate auto-detection. Auto detection
		// is already done at a higher level in constructing UploadMetadata.
		DisableContentTypeDetection: true,

		// Use the supplied metadata lables for the upload.
		Metadata: metadata.Labels(),
	}

	return blob.WriteAll(ctx, path, data, opts)
}