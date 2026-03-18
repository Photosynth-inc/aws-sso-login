package main

import "strings"

// Risk represents the danger level of a command operation.
type Risk int

const (
	RiskRead        Risk = iota // safe: read-only operation
	RiskMutate                  // changes infrastructure state
	RiskDestructive             // deletes or destroys resources
	RiskExec                    // executes code on live systems
	RiskUnknown                 // cannot determine statically
)

func (r Risk) String() string {
	switch r {
	case RiskRead:
		return "read"
	case RiskMutate:
		return "mutate"
	case RiskDestructive:
		return "destructive"
	case RiskExec:
		return "exec"
	case RiskUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// CommandRule defines how to classify operations for a specific CLI tool.
type CommandRule struct {
	Names    []string                       // binary names (e.g. "terraform", "terragrunt")
	Classify func(args []string) (Risk, string) // args[0] is the command itself
}

// commandRules is the registry of all first-class command rules.
// Order does not matter; lookup is by command name.
var commandRules = []CommandRule{
	terraformRule(),
	terragruntRule(),
	cdkRule(),
	samRule(),
	serverlessRule(),
	kubectlRule(),
	helmRule(),
	eksctlRule(),
	pulumiRule(),
	dockerRule(),
}

// commandRuleMap is built at init time for O(1) lookup.
var commandRuleMap map[string]*CommandRule

func init() {
	commandRuleMap = make(map[string]*CommandRule, len(commandRules)*2)
	for i := range commandRules {
		for _, name := range commandRules[i].Names {
			commandRuleMap[name] = &commandRules[i]
		}
	}
}

// lookupCommandRule returns the rule for the given command name (basename),
// or nil if the command is not a first-class tool.
func lookupCommandRule(cmd string) *CommandRule {
	base := lastPathComponent(cmd)
	return commandRuleMap[base]
}

// isFirstClassCommand returns true if the command is recognized by the rule table.
func isFirstClassCommand(cmd string) bool {
	return lookupCommandRule(cmd) != nil
}

// firstClassCommandNames returns all registered command names for quickHit.
func firstClassCommandNames() []string {
	names := make([]string, 0, len(commandRuleMap))
	for name := range commandRuleMap {
		names = append(names, name)
	}
	return names
}

// hasFlag checks if any element in args equals the given flag.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// hasFlagPrefix checks if any element in args starts with the given prefix.
func hasFlagPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

// --- P0: AWS-native and primary IaC tools ---

func terraformRule() CommandRule {
	readSubs := map[string]bool{
		"init": true, "validate": true, "fmt": true, "version": true,
		"providers": true, "show": true, "output": true, "graph": true,
	}
	destructiveSubs := map[string]bool{
		"destroy": true,
	}
	mutateSubs := map[string]bool{
		"apply": true, "import": true, "taint": true, "untaint": true,
	}

	return CommandRule{
		Names: []string{"terraform"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "terraform: subcommand missing"
			}
			sub := args[1]

			if readSubs[sub] {
				return RiskRead, "terraform " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "terraform " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "terraform " + sub
			}

			switch sub {
			case "plan":
				if hasFlag(args, "-destroy") {
					return RiskDestructive, "terraform plan -destroy"
				}
				return RiskRead, "terraform plan"
			case "state":
				if len(args) < 3 {
					return RiskUnknown, "terraform state: subcommand missing"
				}
				switch args[2] {
				case "list", "show", "pull":
					return RiskRead, "terraform state " + args[2]
				case "rm", "mv", "push", "replace-provider":
					return RiskMutate, "terraform state " + args[2]
				default:
					return RiskUnknown, "terraform state: unknown subcommand " + args[2]
				}
			case "workspace":
				if len(args) < 3 {
					return RiskUnknown, "terraform workspace: subcommand missing"
				}
				switch args[2] {
				case "list", "show":
					return RiskRead, "terraform workspace " + args[2]
				case "select", "new":
					return RiskMutate, "terraform workspace " + args[2]
				case "delete":
					return RiskDestructive, "terraform workspace " + args[2]
				default:
					return RiskUnknown, "terraform workspace: unknown subcommand " + args[2]
				}
			default:
				return RiskUnknown, "terraform: unknown subcommand " + sub
			}
		},
	}
}

func terragruntRule() CommandRule {
	readSubs := map[string]bool{
		"hclfmt": true, "validate": true, "plan": true,
		"show": true, "output": true, "graph-dependencies": true,
	}
	destructiveSubs := map[string]bool{
		"destroy": true,
	}
	mutateSubs := map[string]bool{
		"apply": true, "import": true, "taint": true, "untaint": true,
	}

	return CommandRule{
		Names: []string{"terragrunt"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "terragrunt: subcommand missing"
			}
			sub := args[1]

			if readSubs[sub] {
				return RiskRead, "terragrunt " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "terragrunt " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "terragrunt " + sub
			}

			// run-all wraps another subcommand
			if sub == "run-all" && len(args) >= 3 {
				inner := args[2]
				if readSubs[inner] {
					return RiskRead, "terragrunt run-all " + inner
				}
				if destructiveSubs[inner] {
					return RiskDestructive, "terragrunt run-all " + inner
				}
				if mutateSubs[inner] {
					return RiskMutate, "terragrunt run-all " + inner
				}
				return RiskUnknown, "terragrunt run-all: unknown subcommand " + inner
			}

			switch sub {
			case "state":
				if len(args) < 3 {
					return RiskUnknown, "terragrunt state: subcommand missing"
				}
				switch args[2] {
				case "list", "show", "pull":
					return RiskRead, "terragrunt state " + args[2]
				case "rm", "mv", "push", "replace-provider":
					return RiskMutate, "terragrunt state " + args[2]
				default:
					return RiskUnknown, "terragrunt state: unknown subcommand " + args[2]
				}
			default:
				return RiskUnknown, "terragrunt: unknown subcommand " + sub
			}
		},
	}
}

func cdkRule() CommandRule {
	readSubs := map[string]bool{
		"synth": true, "diff": true, "list": true, "ls": true,
		"doctor": true, "metadata": true, "context": true,
		"bootstrap": true,
	}
	mutateSubs := map[string]bool{
		"deploy": true, "rollback": true, "watch": true,
	}
	destructiveSubs := map[string]bool{
		"destroy": true,
	}

	return CommandRule{
		Names: []string{"cdk"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "cdk: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "cdk " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "cdk " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "cdk " + sub
			}
			return RiskUnknown, "cdk: unknown subcommand " + sub
		},
	}
}

func samRule() CommandRule {
	readSubs := map[string]bool{
		"validate": true, "build": true, "package": true,
		"list": true, "logs": true, "local": true,
	}
	mutateSubs := map[string]bool{
		"deploy": true, "sync": true, "publish": true,
	}
	destructiveSubs := map[string]bool{
		"delete": true,
	}

	return CommandRule{
		Names: []string{"sam"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "sam: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "sam " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "sam " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "sam " + sub
			}
			// sam remote invoke
			if sub == "remote" && len(args) >= 3 && args[2] == "invoke" {
				return RiskExec, "sam remote invoke"
			}
			return RiskUnknown, "sam: unknown subcommand " + sub
		},
	}
}

func serverlessRule() CommandRule {
	readSubs := map[string]bool{
		"print": true, "package": true, "info": true, "logs": true,
	}
	mutateSubs := map[string]bool{
		"deploy": true, "rollback": true,
	}
	destructiveSubs := map[string]bool{
		"remove": true,
	}
	execSubs := map[string]bool{
		"invoke": true,
	}

	return CommandRule{
		Names: []string{"serverless", "sls"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "serverless: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "serverless " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "serverless " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "serverless " + sub
			}
			if execSubs[sub] {
				return RiskExec, "serverless " + sub
			}
			// plugin install/uninstall
			if sub == "plugin" && len(args) >= 3 {
				switch args[2] {
				case "install", "uninstall":
					return RiskMutate, "serverless plugin " + args[2]
				case "list":
					return RiskRead, "serverless plugin list"
				}
			}
			return RiskUnknown, "serverless: unknown subcommand " + sub
		},
	}
}

// --- P1: EKS / ECS adjacent ---

func kubectlRule() CommandRule {
	readVerbs := map[string]bool{
		"get": true, "describe": true, "logs": true, "top": true,
		"diff": true, "cluster-info": true, "api-resources": true,
		"api-versions": true, "version": true, "explain": true,
		"config": false, // handled separately
		"auth":  false,
	}
	mutateVerbs := map[string]bool{
		"apply": true, "create": true, "delete": true, "replace": true,
		"patch": true, "edit": true, "scale": true, "autoscale": true,
		"label": true, "annotate": true, "taint": true,
		"cordon": true, "uncordon": true,
	}
	execVerbs := map[string]bool{
		"exec": true, "cp": true, "port-forward": true,
	}
	destructiveVerbs := map[string]bool{
		"drain": true,
	}

	return CommandRule{
		Names: []string{"kubectl"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "kubectl: verb missing"
			}
			verb := args[1]
			if readVerbs[verb] {
				return RiskRead, "kubectl " + verb
			}
			if mutateVerbs[verb] {
				return RiskMutate, "kubectl " + verb
			}
			if execVerbs[verb] {
				return RiskExec, "kubectl " + verb
			}
			if destructiveVerbs[verb] {
				return RiskDestructive, "kubectl " + verb
			}
			// rollout restart
			if verb == "rollout" && len(args) >= 3 {
				switch args[2] {
				case "status", "history":
					return RiskRead, "kubectl rollout " + args[2]
				case "restart", "undo", "pause", "resume":
					return RiskMutate, "kubectl rollout " + args[2]
				}
			}
			// set image/env
			if verb == "set" {
				return RiskMutate, "kubectl set"
			}
			// auth can-i
			if verb == "auth" {
				return RiskRead, "kubectl auth"
			}
			// config
			if verb == "config" && len(args) >= 3 {
				switch args[2] {
				case "view", "get-contexts", "get-clusters", "current-context":
					return RiskRead, "kubectl config " + args[2]
				default:
					return RiskMutate, "kubectl config " + args[2]
				}
			}
			return RiskUnknown, "kubectl: unknown verb " + verb
		},
	}
}

func helmRule() CommandRule {
	readSubs := map[string]bool{
		"list": true, "ls": true, "status": true, "history": true,
		"show": true, "search": true, "template": true, "lint": true,
		"get": true, "env": true, "version": true,
	}
	mutateSubs := map[string]bool{
		"install": true, "upgrade": true, "rollback": true,
	}
	destructiveSubs := map[string]bool{
		"uninstall": true,
	}

	return CommandRule{
		Names: []string{"helm"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "helm: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "helm " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "helm " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "helm " + sub
			}
			// helm diff is a plugin that's read-only
			if sub == "diff" {
				return RiskRead, "helm diff"
			}
			// repo add/remove
			if sub == "repo" && len(args) >= 3 {
				switch args[2] {
				case "list", "search", "index":
					return RiskRead, "helm repo " + args[2]
				case "add", "remove", "update":
					return RiskMutate, "helm repo " + args[2]
				}
			}
			return RiskUnknown, "helm: unknown subcommand " + sub
		},
	}
}

func eksctlRule() CommandRule {
	return CommandRule{
		Names: []string{"eksctl"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "eksctl: subcommand missing"
			}
			sub := args[1]
			switch sub {
			case "get", "version":
				return RiskRead, "eksctl " + sub
			case "create", "upgrade", "scale", "set", "enable", "disable":
				return RiskMutate, "eksctl " + sub
			case "delete", "drain":
				return RiskDestructive, "eksctl " + sub
			case "utils":
				if len(args) >= 3 {
					if strings.HasPrefix(args[2], "describe-") {
						return RiskRead, "eksctl utils " + args[2]
					}
					return RiskMutate, "eksctl utils " + args[2]
				}
				return RiskUnknown, "eksctl utils: subcommand missing"
			default:
				return RiskUnknown, "eksctl: unknown subcommand " + sub
			}
		},
	}
}

func pulumiRule() CommandRule {
	readSubs := map[string]bool{
		"preview": true, "about": true, "whoami": true,
		"logs": true, "version": true,
	}
	mutateSubs := map[string]bool{
		"up": true, "import": true, "refresh": true, "cancel": true,
	}
	destructiveSubs := map[string]bool{
		"destroy": true,
	}

	return CommandRule{
		Names: []string{"pulumi"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "pulumi: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "pulumi " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "pulumi " + sub
			}
			if destructiveSubs[sub] {
				return RiskDestructive, "pulumi " + sub
			}
			switch sub {
			case "stack":
				if len(args) < 3 {
					return RiskUnknown, "pulumi stack: subcommand missing"
				}
				switch args[2] {
				case "ls", "output", "history", "tag":
					return RiskRead, "pulumi stack " + args[2]
				case "init", "select":
					return RiskMutate, "pulumi stack " + args[2]
				case "rm":
					return RiskDestructive, "pulumi stack rm"
				default:
					return RiskUnknown, "pulumi stack: unknown subcommand " + args[2]
				}
			case "state":
				if len(args) < 3 {
					return RiskUnknown, "pulumi state: subcommand missing"
				}
				switch args[2] {
				case "delete", "unprotect":
					return RiskMutate, "pulumi state " + args[2]
				default:
					return RiskUnknown, "pulumi state: unknown subcommand " + args[2]
				}
			case "config":
				if len(args) < 3 {
					return RiskRead, "pulumi config"
				}
				switch args[2] {
				case "get", "refresh":
					return RiskRead, "pulumi config " + args[2]
				case "set", "set-all", "rm", "rm-all":
					return RiskMutate, "pulumi config " + args[2]
				default:
					return RiskUnknown, "pulumi config: unknown subcommand " + args[2]
				}
			default:
				return RiskUnknown, "pulumi: unknown subcommand " + sub
			}
		},
	}
}

func dockerRule() CommandRule {
	readSubs := map[string]bool{
		"ps": true, "images": true, "inspect": true, "logs": true,
		"stats": true, "events": true, "pull": true, "version": true,
		"info": true, "history": true, "tag": false,
	}
	mutateSubs := map[string]bool{
		"build": true, "push": true, "rm": true, "rmi": true,
		"stop": true, "kill": true, "restart": true, "tag": true,
	}
	execSubs := map[string]bool{
		"run": true, "exec": true,
	}

	return CommandRule{
		Names: []string{"docker"},
		Classify: func(args []string) (Risk, string) {
			if len(args) < 2 {
				return RiskUnknown, "docker: subcommand missing"
			}
			sub := args[1]
			if readSubs[sub] {
				return RiskRead, "docker " + sub
			}
			if mutateSubs[sub] {
				return RiskMutate, "docker " + sub
			}
			if execSubs[sub] {
				return RiskExec, "docker " + sub
			}
			// docker compose
			if sub == "compose" && len(args) >= 3 {
				composeSub := args[2]
				switch composeSub {
				case "ps", "logs", "config", "ls", "images", "top", "version":
					return RiskRead, "docker compose " + composeSub
				case "up", "down", "restart", "rm", "stop", "kill", "start", "create":
					return RiskMutate, "docker compose " + composeSub
				case "exec", "run":
					return RiskExec, "docker compose " + composeSub
				default:
					return RiskUnknown, "docker compose: unknown subcommand " + composeSub
				}
			}
			// docker buildx
			if sub == "buildx" {
				return RiskMutate, "docker buildx"
			}
			// network/volume subcommands
			if sub == "network" || sub == "volume" {
				if len(args) >= 3 {
					switch args[2] {
					case "ls", "inspect":
						return RiskRead, "docker " + sub + " " + args[2]
					default:
						return RiskMutate, "docker " + sub + " " + args[2]
					}
				}
			}
			return RiskUnknown, "docker: unknown subcommand " + sub
		},
	}
}
