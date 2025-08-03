package pbft

type Logger interface {
	Printf(format string, args ...interface{})
	Print(args ...interface{})
}
