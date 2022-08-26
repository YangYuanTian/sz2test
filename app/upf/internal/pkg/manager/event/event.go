package event

type Model interface {
}

type Event interface {
	Type() Type
	UserName() string
	Do(model Model) error
}

type Type int
