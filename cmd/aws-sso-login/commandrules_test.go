package main

import (
	"strings"
	"testing"
)

func TestClassifyCommands(t *testing.T) {
	tests := []struct {
		command string
		verdict Verdict
		risk    Risk
	}{
		// --- terraform ---
		{"terraform plan", VerdictAllow, RiskRead},
		{"terraform plan -destroy", VerdictBlock, RiskDestructive},
		{"terraform apply", VerdictBlock, RiskMutate},
		{"terraform destroy", VerdictBlock, RiskDestructive},
		{"terraform validate", VerdictAllow, RiskRead},
		{"terraform fmt", VerdictAllow, RiskRead},
		{"terraform init", VerdictAllow, RiskRead},
		{"terraform show", VerdictAllow, RiskRead},
		{"terraform output", VerdictAllow, RiskRead},
		{"terraform import addr id", VerdictBlock, RiskMutate},
		{"terraform taint aws_instance.foo", VerdictBlock, RiskMutate},
		{"terraform state list", VerdictAllow, RiskRead},
		{"terraform state show aws_instance.foo", VerdictAllow, RiskRead},
		{"terraform state rm aws_instance.foo", VerdictBlock, RiskMutate},
		{"terraform state mv a b", VerdictBlock, RiskMutate},
		{"terraform workspace list", VerdictAllow, RiskRead},
		{"terraform workspace delete dev", VerdictBlock, RiskDestructive},
		{"terraform workspace new staging", VerdictBlock, RiskMutate},

		// --- terragrunt ---
		{"terragrunt plan", VerdictAllow, RiskRead},
		{"terragrunt apply", VerdictBlock, RiskMutate},
		{"terragrunt destroy", VerdictBlock, RiskDestructive},
		{"terragrunt validate", VerdictAllow, RiskRead},
		{"terragrunt run-all apply", VerdictBlock, RiskMutate},
		{"terragrunt run-all destroy", VerdictBlock, RiskDestructive},
		{"terragrunt run-all plan", VerdictAllow, RiskRead},
		{"terragrunt state list", VerdictAllow, RiskRead},
		{"terragrunt state rm foo", VerdictBlock, RiskMutate},

		// --- cdk ---
		{"cdk synth", VerdictAllow, RiskRead},
		{"cdk diff", VerdictAllow, RiskRead},
		{"cdk list", VerdictAllow, RiskRead},
		{"cdk deploy", VerdictBlock, RiskMutate},
		{"cdk destroy", VerdictBlock, RiskDestructive},
		{"cdk watch", VerdictBlock, RiskMutate},

		// --- sam ---
		{"sam validate", VerdictAllow, RiskRead},
		{"sam build", VerdictAllow, RiskRead},
		{"sam deploy", VerdictBlock, RiskMutate},
		{"sam delete", VerdictBlock, RiskDestructive},
		{"sam sync", VerdictBlock, RiskMutate},
		{"sam remote invoke func", VerdictBlock, RiskExec},
		{"sam logs", VerdictAllow, RiskRead},

		// --- serverless / sls ---
		{"serverless print", VerdictAllow, RiskRead},
		{"serverless package", VerdictAllow, RiskRead},
		{"serverless deploy", VerdictBlock, RiskMutate},
		{"serverless remove", VerdictBlock, RiskDestructive},
		{"serverless invoke --function hello", VerdictBlock, RiskExec},
		{"sls deploy", VerdictBlock, RiskMutate},
		{"sls info", VerdictAllow, RiskRead},
		{"sls logs -f hello", VerdictAllow, RiskRead},

		// --- kubectl ---
		{"kubectl get pods", VerdictAllow, RiskRead},
		{"kubectl describe pod foo", VerdictAllow, RiskRead},
		{"kubectl logs foo", VerdictAllow, RiskRead},
		{"kubectl apply -f k8s.yaml", VerdictBlock, RiskMutate},
		{"kubectl delete pod foo", VerdictBlock, RiskMutate},
		{"kubectl exec -it foo -- bash", VerdictBlock, RiskExec},
		{"kubectl drain node1", VerdictBlock, RiskDestructive},
		{"kubectl diff -f k8s.yaml", VerdictAllow, RiskRead},
		{"kubectl rollout status deploy/foo", VerdictAllow, RiskRead},
		{"kubectl rollout restart deploy/foo", VerdictBlock, RiskMutate},

		// --- helm ---
		{"helm list", VerdictAllow, RiskRead},
		{"helm status release", VerdictAllow, RiskRead},
		{"helm template chart", VerdictAllow, RiskRead},
		{"helm install release chart", VerdictBlock, RiskMutate},
		{"helm upgrade release chart", VerdictBlock, RiskMutate},
		{"helm uninstall release", VerdictBlock, RiskDestructive},
		{"helm diff upgrade release chart", VerdictAllow, RiskRead},

		// --- eksctl ---
		{"eksctl get cluster", VerdictAllow, RiskRead},
		{"eksctl version", VerdictAllow, RiskRead},
		{"eksctl create cluster", VerdictBlock, RiskMutate},
		{"eksctl delete cluster --name foo", VerdictBlock, RiskDestructive},

		// --- pulumi ---
		{"pulumi preview", VerdictAllow, RiskRead},
		{"pulumi up", VerdictBlock, RiskMutate},
		{"pulumi destroy", VerdictBlock, RiskDestructive},
		{"pulumi stack ls", VerdictAllow, RiskRead},
		{"pulumi stack rm foo", VerdictBlock, RiskDestructive},

		// --- docker ---
		{"docker ps", VerdictAllow, RiskRead},
		{"docker images", VerdictAllow, RiskRead},
		{"docker logs container", VerdictAllow, RiskRead},
		{"docker run -it ubuntu bash", VerdictBlock, RiskExec},
		{"docker exec -it container bash", VerdictBlock, RiskExec},
		{"docker push image:tag", VerdictBlock, RiskMutate},
		{"docker rm container", VerdictBlock, RiskMutate},
		{"docker compose ps", VerdictAllow, RiskRead},
		{"docker compose up -d", VerdictBlock, RiskMutate},
		{"docker compose down", VerdictBlock, RiskMutate},
		{"docker compose exec web bash", VerdictBlock, RiskExec},

		// --- non-classified commands pass through ---
		{"echo hello", VerdictAllow, RiskRead},
		{"ls -la", VerdictAllow, RiskRead},
		{"cat file.txt", VerdictAllow, RiskRead},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := AnalyzeCommand(tt.command)
			if got.Verdict != tt.verdict {
				t.Errorf("AnalyzeCommand(%q) verdict=%v, want %v (reason: %q)",
					tt.command, got.Verdict, tt.verdict, got.Reason)
			}
			if got.Command != "" && got.CommandRisk != tt.risk {
				t.Errorf("AnalyzeCommand(%q) risk=%v, want %v (reason: %q)",
					tt.command, got.CommandRisk, tt.risk, got.Reason)
			}
		})
	}
}

func TestClassifyCommandsWithWrappers(t *testing.T) {
	tests := []struct {
		command string
		verdict Verdict
	}{
		{"sudo terraform apply", VerdictBlock},
		{"env terraform destroy", VerdictBlock},
		{"command terraform plan", VerdictAllow},
		{"nice -n 5 cdk deploy", VerdictBlock},

		// nested shell
		{"bash -c 'terraform apply'", VerdictBlock},
		{"sh -c 'sam deploy'", VerdictBlock},
		{"bash -c 'terraform plan'", VerdictAllow},

		// package runners
		{"npx cdk deploy", VerdictBlock},
		{"npx cdk diff", VerdictAllow},
		{"npx serverless deploy", VerdictBlock},
		{"npx --yes cdk deploy", VerdictBlock},
		{"bunx cdk destroy", VerdictBlock},
		{"yarn cdk deploy", VerdictBlock},
		{"yarn terraform plan", VerdictAllow},
		{"pnpm exec cdk deploy", VerdictBlock},
		{"pnpm dlx serverless deploy", VerdictBlock},
		{"pnpm cdk diff", VerdictAllow},

		// package runners + other wrappers
		{"sudo npx cdk deploy", VerdictBlock},
		{"env npx terraform apply", VerdictBlock},
		{"bash -c 'npx cdk deploy'", VerdictBlock},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := AnalyzeCommand(tt.command)
			if got.Verdict != tt.verdict {
				t.Errorf("AnalyzeCommand(%q) verdict=%v, want %v (reason: %q)",
					tt.command, got.Verdict, tt.verdict, got.Reason)
			}
		})
	}
}

func TestClassifyCommandsDynamic(t *testing.T) {
	tests := []struct {
		command string
		verdict Verdict
	}{
		{"terraform $ACTION", VerdictUnknown},
		{"kubectl $VERB pods", VerdictUnknown},
		{"cdk $CMD", VerdictUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := AnalyzeCommand(tt.command)
			if got.Verdict != tt.verdict {
				t.Errorf("AnalyzeCommand(%q) verdict=%v, want %v (reason: %q)",
					tt.command, got.Verdict, tt.verdict, got.Reason)
			}
		})
	}
}

func TestRunGuardClassifyCommands(t *testing.T) {
	makePayload := func(cmd string) string {
		cmd = strings.ReplaceAll(cmd, `\`, `\\`)
		cmd = strings.ReplaceAll(cmd, `"`, `\"`)
		return `{"hook_event_name":"PreToolUse","tool_input":{"command":"` + cmd + `"}}`
	}

	tests := []struct {
		name      string
		stdin     string
		opts      guardOptions
		wantBlock bool
	}{
		// --readonly-only blocks mutate/destructive commands
		{"block terraform apply", makePayload("terraform apply"), guardOptions{readOnly: true}, true},
		{"block terraform destroy", makePayload("terraform destroy"), guardOptions{readOnly: true}, true},
		{"allow terraform plan", makePayload("terraform plan"), guardOptions{readOnly: true}, false},
		{"block cdk deploy", makePayload("cdk deploy"), guardOptions{readOnly: true}, true},
		{"allow cdk diff", makePayload("cdk diff"), guardOptions{readOnly: true}, false},

		// aws profile check + command risk both active
		{"block aws non-ro", makePayload("aws s3 ls --profile prod"), guardOptions{readOnly: true}, true},
		{"allow aws ro", makePayload("aws s3 ls --profile prod-ro"), guardOptions{readOnly: true}, false},

		// without --readonly-only: nothing blocked
		{"allow terraform apply without flag", makePayload("terraform apply"), guardOptions{}, false},

		// fail-open
		{"allow unknown fail-open", makePayload("terraform $ACTION"), guardOptions{readOnly: true, failOpen: true}, false},
		{"block unknown fail-closed", makePayload("terraform $ACTION"), guardOptions{readOnly: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.stdin)
			blocked, _ := runGuard(tt.opts, r)
			if blocked != tt.wantBlock {
				t.Errorf("runGuard(%+v, stdin) blocked=%v, want %v",
					tt.opts, blocked, tt.wantBlock)
			}
		})
	}
}
