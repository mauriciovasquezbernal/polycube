package types

type FirewallAction struct {
	PodLabels       map[string]string
	NamespaceName   string
	NamespaceLabels map[string]string
	Key             string
	Templates       ParsedRules
}

type ProtoPort struct {
	Protocol string
	Port     int32
}

type FirewallActionType string

const (
	Forward       = "forward"
	Drop          = "drop"
	Log           = "log"
	SameNamespace = "#SAME-NAMESPACE#"
)
