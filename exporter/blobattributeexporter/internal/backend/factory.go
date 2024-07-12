// Package "backend" provides utilities for writing to a general blob storage system.
//
// The file "factory.go" provides a means of instantiating a BackendRegistry.
package backend

// registryImpl is the main implementation of "BackendRegistry".
type registryImpl struct {
	// schemeToBackend contains a mapping from a URI scheme (e.g.
	// "gs", "s3", "azblob", etc.) to a corresponding backend.
	schemeToBackend map[string]BlobStorageBackend
}

// "GetBackendForUri" implements "BackendRegistry.GetBackendForUri".
func (r *registryImpl) GetBackendForUri(uri string) (BlobStorageBackend, err) {
	scheme, _ := strings.SplitN(uri, "://", 1)
	entry, ok := r.schemeToBackend[scheme]
	if !ok {
		return nil, fmt.Errorf("URI %v not recognized; no implementation registered for scheme %v", uri, scheme)
	}
	return entry, nil
}

// NewRegistry instantiates a new backend registry.
func NewRegistry() (BackendRegistry, err) {
	return &registryImpl{
		schemeToBackend: map[string]BlobStorageBackend{
			"azblob": &cdkBlobStorageBackend{},
			"gs": &cdkBlobStorageBackend{},
			"s3": &cdkBlobStorageBackend{},
		},
	}
}
