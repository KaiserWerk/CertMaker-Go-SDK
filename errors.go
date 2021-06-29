package certmaker

type ErrStillValid struct {}

func (e ErrStillValid) Error() string {
	return "The certificate is still valid"
}
