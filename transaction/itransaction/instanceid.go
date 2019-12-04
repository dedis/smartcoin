package itransaction

// InstanceID ...
type InstanceID interface {
	GetInstanceID() [32]byte
	Slice() []byte
}
